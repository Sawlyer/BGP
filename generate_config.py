import json
from ipaddress import IPv6Network, IPv6Interface

class NetworkAutomator:
    def __init__(self, intent_file):
        with open(intent_file) as f:
            self.data = json.load(f)
        
        self.ip_allocations = {}
        self.inter_links = {}  # Stocke les sous-réseaux inter-AS
        self.used_subnets = {} # Tient à jour les sous-réseaux utilisés par AS
        self.generate_addressing()

    def generate_addressing(self):
        """Alloue les adresses IPv6, y compris les liens inter-AS (un seul /64 partagé)."""
        for as_info in self.data['ASes']:
            asn = as_info['asn']
            asn_str = str(asn)

            phy_range = IPv6Network(self.data['subnetAllocation']['asAllocation'][asn_str]['physicalRange'])
            loop_range = IPv6Network(self.data['subnetAllocation']['asAllocation'][asn_str]['loopbackRange'])
            self.used_subnets[asn] = set()

            # ---------- Allocation des loopbacks ----------
            # 1 IP / router dans l'AS
            loopback_subnets = loop_range.subnets(new_prefix=128)
            for router_index, router in enumerate(as_info['routers'], start=1):
                loopback_addr = loop_range.network_address + router_index
                self.ip_allocations[f"{asn_str}_{router}"] = {'loopback': str(loopback_addr)}

            # ---------- Générer tous les /64 pour l'AS (intra-AS) ----------
            all_subnets = list(phy_range.subnets(new_prefix=64))
            subnet_index = 0

            # ---------- Parcourir la topologie de l'AS (liens) ----------
            for link in as_info['topology']['links']:
                is_inter_as = False
                if isinstance(link, dict):  # Gestion du format { "endpoints": [...], "cost": ... }
                    endpoints = link["endpoints"]
                else:  # Ancien format (liste simple)
                    endpoints = link

                is_inter_as = ('interAS' in endpoints)
                subnet = None

                if is_inter_as:
                    # ---- Lien inter-AS ----
                    router_names = [ep.split(':')[0] for ep in endpoints if ep != 'interAS']
                    key = tuple(sorted(router_names))  # Clé unique pour inter-AS

                    if key in self.inter_links:
                        subnet = self.inter_links[key]
                    else:
                        first_asn = next(asn for asn in self.used_subnets if any(r in as_info['routers'] for r in router_names))
                        first_asn_str = str(first_asn)
                        inter_as_subnets = list(IPv6Network(self.data['subnetAllocation']['asAllocation'][first_asn_str]['physicalRange']).subnets(new_prefix=64))

                        for candidate in inter_as_subnets:
                            if candidate not in self.used_subnets[first_asn]:
                                subnet = candidate
                                self.used_subnets[first_asn].add(subnet)
                                self.inter_links[key] = subnet
                                break
                        else:
                            raise ValueError(f"Plus de sous-réseaux disponibles pour lien inter-AS {key}")

                    link_id = f"interAS_{'_'.join(router_names)}"
                    self.ip_allocations[link_id] = {'subnet': subnet, 'interfaces': {}}
                    host_index = 1
                    for ep in endpoints:
                        if ep == 'interAS':
                            continue
                        router, iface = ep.split(':')
                        address = subnet.network_address + host_index
                        self.ip_allocations[link_id]['interfaces'][f"{router}:{iface}"] = str(address)
                        host_index += 1

                else:
                    # ---- Lien intra-AS ----
                    while subnet_index < len(all_subnets):
                        candidate = all_subnets[subnet_index]
                        if candidate not in self.used_subnets[asn]:
                            subnet = candidate
                            self.used_subnets[asn].add(subnet)
                            subnet_index += 1
                            break
                        subnet_index += 1

                    if not subnet:
                        raise ValueError(f"Plus de sous-réseaux /64 disponibles pour AS {asn}")

                    link_id = f"{asn_str}_link_{as_info['topology']['links'].index(link)}"
                    self.ip_allocations[link_id] = {'subnet': subnet, 'interfaces': {}}

                    host_index = 1
                    for ep in endpoints:
                        router, iface = ep.split(':')
                        address = subnet.network_address + host_index
                        self.ip_allocations[link_id]['interfaces'][f"{router}:{iface}"] = str(address)
                        host_index += 1


    # ---------------------------------------------------------------------
    #           GENERATION DE LA CONFIG
    # ---------------------------------------------------------------------
    def generate_router_config(self, asn, router):
        """Génère la configuration pour un routeur d'AS donné."""
        config = []
        config.append("version 15.2")
        config.append("ipv6 unicast-routing")
        config.append("ipv6 cef")
        config.append("!")
        config.append(f"hostname {router}")

        as_info = next(a for a in self.data['ASes'] if a['asn'] == asn)

        configured_interfaces = set()
        used_interfaces = {i['name'] for i in self.get_router_interfaces(asn, router)}

        # -- Config Interfaces --
        for iface in self.get_router_interfaces(asn, router):
            if iface['name'] in configured_interfaces:
                continue
            config.append(f"interface {iface['name']}")
            config.append(" no ip address")
            config.append(f" ipv6 address {iface['ipv6']}")
            if iface['name'].startswith("FastEthernet"):
                config.append(" duplex full")
            elif iface['name'].startswith("GigabitEthernet"):
                config.append(" negotiation auto")

            if iface['name'] in used_interfaces:
                config.append(" no shutdown")
            else:
                config.append(" shutdown")

            # Activation IGP si pas loopback
            if not iface['name'].lower().startswith("loopback"):
                if as_info['igp']['type'].upper() == "RIP":
                    config.append(" ipv6 rip RIPng enable")
                elif as_info['igp']['type'].upper() == "OSPF":
                    config.append(" ipv6 ospf 1 area 0")

            config.append("!")
            configured_interfaces.add(iface['name'])

        # -- Config IGP (RIP/OSPF) --
        config += self.generate_igp_config(as_info, router)

        # -- Config BGP --
        config += self.generate_bgp_config(as_info, router)

        config.append("end")
        return "\n".join(config)


    def get_router_interfaces(self, asn, router):
        """Retourne toutes les interfaces (loopback + physiques) du routeur."""
        asn_str = str(asn)
        interfaces = []

        # 1) Loopback
        loopback_ip = self.ip_allocations[f"{asn_str}_{router}"]['loopback']
        interfaces.append({
            "name": "Loopback0",
            "ipv6": f"{loopback_ip}/128"
        })

        # 2) Physiques
        for link_id, link_data in self.ip_allocations.items():
            if "interfaces" not in link_data:
                continue

            for intf_key, ip_str in link_data["interfaces"].items():
                r_name, iface_name = intf_key.split(":", maxsplit=1)
                if r_name == router:
                    interfaces.append({
                        "name": iface_name,
                        "ipv6": f"{ip_str}/64"
                    })

        return interfaces

    def generate_igp_config(self, as_info, router):
        config = []
        asn_str = str(as_info['asn'])
        igp_type = as_info['igp']['type'].upper()

        if igp_type == "RIP":
            config.append("ipv6 router rip RIPng")
            config.append(" redistribute connected")
            config.append("!")
            # Activer RIPng sur chaque interface non-loopback
            for iface in self.get_router_interfaces(as_info['asn'], router):
                if not iface['name'].lower().startswith('loopback'):
                    config.append(f"interface {iface['name']}")
                    config.append(" ipv6 rip RIPng enable")
                    config.append("!")
        elif igp_type == "OSPF":
            config.append("ipv6 router ospf 1")
            loopback_ip = self.ip_allocations[f"{asn_str}_{router}"]['loopback']
            config.append(f" router-id {self.router_id_from_loopback(loopback_ip)}")
            config.append("!")
            for iface in self.get_router_interfaces(as_info['asn'], router):
                config.append(f"interface {iface['name']}")
                config.append(" ipv6 ospf 1 area 0")

                # Vérifier si un coût spécifique est défini pour ce lien
                for link in as_info.get('topology', {}).get('links', []):
                    if isinstance(link, dict) and 'cost' in link:
                        if any(router in ep for ep in link["endpoints"]):
                            cost = link["cost"]
                            config.append(f" ipv6 ospf cost {cost}")

                config.append("!")
        return config

    def generate_bgp_config(self, as_info, router):
        config = []
        router_id = self.router_id_from_router_name(router)
        asn_str = str(as_info['asn'])

        config.append(f"router bgp {as_info['asn']}")
        config.append(" no bgp default ipv4-unicast")
        config.append(f" bgp router-id {router_id}")
        config.append(" address-family ipv6 unicast")

        # -- Réseaux à annoncer --
        networks_to_advertise = set()
        for iface in self.get_router_interfaces(as_info['asn'], router):
            base_ip = iface['ipv6'].split('/')[0]
            if iface['name'].lower().startswith("loopback"):
                networks_to_advertise.add(base_ip + "/128")
            else:
                subnet64 = IPv6Network(base_ip + "/64", strict=False)
                networks_to_advertise.add(str(subnet64))
        for net in networks_to_advertise:
            config.append(f"  network {net}")

        # -- iBGP Peers --
        rr_server = as_info['routers'][router]['bgp'].get('rr_server', False)
        if 'iBGPpeers' in as_info['routers'][router]['bgp']:
            for peer_name in as_info['routers'][router]['bgp']['iBGPpeers']:
                peer_loop = self.ip_allocations[f"{asn_str}_{peer_name}"]['loopback']
                config.append(f"  neighbor {peer_loop} remote-as {as_info['asn']}")
                config.append(f"  neighbor {peer_loop} update-source Loopback0")
                config.append(f"  neighbor {peer_loop} activate")
                config.append(f"  neighbor {peer_loop} send-community")
            if rr_server:
                for peer_name in as_info['routers'][router]['bgp']['iBGPpeers']:
                    peer_loop = self.ip_allocations[f"{asn_str}_{peer_name}"]['loopback']
                    config.append(f"  neighbor {peer_loop} route-reflector-client")

        # -- eBGP Peers --
        if 'eBGPpeers' in as_info['routers'][router]['bgp']:
            for peer_name in as_info['routers'][router]['bgp']['eBGPpeers']:
                peer_as_info = next(a for a in self.data['ASes'] if peer_name in a['routers'])
                peer_asn = peer_as_info['asn']
                peer_ip = self.find_ebgp_peer_ip_physical(router, peer_name, asn_str, str(peer_asn))
                config.append(f"  neighbor {peer_ip} remote-as {peer_asn}")
                config.append(f"  neighbor {peer_ip} activate")
                # Gestion des politiques
                bgp_policies = as_info['routers'][router]['bgp'].get('policies', {})
                neighbor_policies = bgp_policies.get('neighbors', {})
                if peer_name in neighbor_policies:
                    policy = neighbor_policies[peer_name]
                    community = policy.get("community", "0")
                    local_pref = policy.get("local_pref", None)
                    filter_name = policy.get("filter", None)
                    # Appliquer un route-map sur les routes entrantes pour taguer
                    if community and community != "0":
                        config.append(f"  neighbor {peer_ip} route-map TAG_IN in")
                        # Vous pouvez aussi ajouter la configuration globale du route-map TAG_IN ici
                        config.append("!")
                        config.append("route-map TAG_IN permit 10")
                        config.append(f" set community {community} additive")
                        if local_pref is not None:
                            config.append(f" set local-preference {local_pref}")
                        config.append("!")
                    # Appliquer un route-map sur les routes sortantes pour filtrer
                    if filter_name:
                        config.append(f"  neighbor {peer_ip} route-map {filter_name} out")

        # -- Redistribution de l'IGP dans BGP --
        igp_type = as_info['igp']['type'].upper()
        if igp_type == "RIP":
            config.append("  redistribute rip RIPng")
        elif igp_type == "OSPF":
            config.append("  redistribute ospf 1")

        config.append(" exit-address-family")
        config.append("!")
        return config


    def find_ebgp_peer_ip_physical(self, local_router, peer_router, local_asn_str, peer_asn_str):
        """Trouver l'adresse IPv6 interAS du peer (on évite la loopback)."""
        for link_id, link_data in self.ip_allocations.items():
            if not link_id.startswith("interAS_"):
                continue

            # Vérif si ce lien connecte local_router et peer_router
            routers_found = set()
            for intf_key in link_data["interfaces"]:
                r_name, iface = intf_key.split(":", 1)
                routers_found.add(r_name)

            if local_router in routers_found and peer_router in routers_found:
                # On retourne l'IP associée au peer
                for intf_key, ip_str in link_data["interfaces"].items():
                    r_name, iface = intf_key.split(":", 1)
                    if r_name == peer_router:
                        return ip_str.split('/')[0]

        # Fallback sur loopback
        return self.ip_allocations[f"{peer_asn_str}_{peer_router}"]['loopback']

    def router_id_from_router_name(self, router_name):
        """Ex: R1 -> 1.1.1.1, R2 -> 2.2.2.2, etc."""
        try:
            num = int(router_name[1:])
            return f"{num}.{num}.{num}.{num}"
        except:
            return "1.1.1.1"

    def router_id_from_loopback(self, loopback_ip):
        """
        Convertit l'IPv6 (ex: 2001:db8:2::1) en pseudo router-id IPv4.
        On prend le dernier hextet, on le convertit en int, ex: 0x1 -> 1.0.0.1
        """
        last_chunk = loopback_ip.split(':')[-1].split('/')[0]
        try:
            val = int(last_chunk, 16)
        except ValueError:
            val = 1
        val = val & 0xFFFFFFFF
        return f"{(val >> 24) & 0xFF}.{(val >> 16) & 0xFF}.{(val >> 8) & 0xFF}.{val & 0xFF}"

# ========================================================================
#                            MAIN
# ========================================================================
if __name__ == "__main__":
    automator = NetworkAutomator('network_intent.json')
    for as_info in automator.data['ASes']:
        asn = as_info['asn']
        for router in as_info['routers']:
            cfg = automator.generate_router_config(asn, router)
            filename = f"{router}.cfg"
            with open(filename, "w") as f:
                f.write(cfg)
            print(f"Configuration générée pour {router} (AS {asn}) => {filename}")