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
                is_inter_as = ('interAS' in link)
                subnet = None

                if is_inter_as:
                    # ---- Lien inter-AS ----
                    endpoints = []
                    for item in link:
                        if item == 'interAS':
                            continue
                        router_name = item.split(':')[0]
                        # Chercher l'AS de ce router_name
                        for as_entry in self.data['ASes']:
                            if router_name in as_entry['routers']:
                                endpoints.append((as_entry['asn'], router_name))
                                break

                    # Tri pour la clé unique
                    key = tuple(sorted(endpoints, key=lambda x: (x[0], x[1])))

                    if key in self.inter_links:
                        # On a déjà attribué un subnet pour ces deux routeurs
                        subnet = self.inter_links[key]
                    else:
                        # Choisir un subnet depuis l'AS "plus petit" dans le tuple
                        first_asn = key[0][0]
                        first_asn_str = str(first_asn)
                        first_asn_range = IPv6Network(self.data['subnetAllocation']['asAllocation'][first_asn_str]['physicalRange'])
                        inter_as_subnets = list(first_asn_range.subnets(new_prefix=64))

                        for candidate in inter_as_subnets:
                            if candidate not in self.used_subnets[first_asn]:
                                subnet = candidate
                                self.used_subnets[first_asn].add(subnet)
                                self.inter_links[key] = subnet
                                break
                        else:
                            raise ValueError(f"Plus de sous-réseaux disponibles pour lien inter-AS {key}")

                    # Créer une entrée interAS_xxx dans ip_allocations
                    link_id = f"interAS_{'_'.join([r[1] for r in key])}"
                    self.ip_allocations[link_id] = {'subnet': subnet, 'interfaces': {}}
                    host_index = 1
                    for item in link:
                        if item == 'interAS':
                            continue
                        router, iface = item.split(':')
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

                # Qu'il soit inter ou intra, on crée aussi l'entrée <asn>_link_<index>
                link_id = f"{asn_str}_link_{as_info['topology']['links'].index(link)}"
                self.ip_allocations[link_id] = {
                    'subnet': subnet,
                    'interfaces': {}
                }
                host_index = 1
                for item in link:
                    if item == 'interAS':
                        continue
                    router, iface = item.split(':')
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

        # -- network ...
        networks_to_advertise = set()
        for iface in self.get_router_interfaces(as_info['asn'], router):
            base_ip = iface['ipv6'].split('/')[0]
            if iface['name'].lower().startswith("loopback"):
                networks_to_advertise.add(base_ip + "/128")
            else:
                # /64
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
                # iBGP => update-source Loopback0
                config.append(f"  neighbor {peer_loop} update-source Loopback0")
                config.append(f"  neighbor {peer_loop} activate")

            # -- Si on est "rr_server": neighbor X route-reflector-client
            if rr_server:
                for peer_name in as_info['routers'][router]['bgp']['iBGPpeers']:
                    peer_loop = self.ip_allocations[f"{asn_str}_{peer_name}"]['loopback']
                    config.append(f"  neighbor {peer_loop} route-reflector-client")

        # -- eBGP Peers --
        if 'eBGPpeers' in as_info['routers'][router]['bgp']:
            for peer_name in as_info['routers'][router]['bgp']['eBGPpeers']:
                # Trouver l'AS du peer
                peer_as_info = next(a for a in self.data['ASes'] if peer_name in a['routers'])
                peer_asn = peer_as_info['asn']
                # Adresse physique
                peer_ip = self.find_ebgp_peer_ip_physical(router, peer_name, asn_str, str(peer_asn))
                config.append(f"  neighbor {peer_ip} remote-as {peer_asn}")
                config.append(f"  neighbor {peer_ip} activate")

        # -- Redistribution de l'IGP dans BGP
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