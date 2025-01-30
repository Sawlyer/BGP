import json
from ipaddress import IPv6Network, IPv6Interface

class NetworkAutomator:
    def __init__(self, intent_file):
        with open(intent_file) as f:
            self.data = json.load(f)
        
        self.ip_allocations = {}
        self.generate_addressing()

    def generate_addressing(self):
        """Alloue automatiquement les adresses IPv6 à partir de l'intent."""
        for as_info in self.data['ASes']:
            asn_str = str(as_info['asn'])
            phy_range = IPv6Network(self.data['subnetAllocation']['asAllocation'][asn_str]['physicalRange'])
            loop_range = IPv6Network(self.data['subnetAllocation']['asAllocation'][asn_str]['loopbackRange'])

            # Allocation des loopbacks
            loopback_subnets = loop_range.subnets(new_prefix=128)  # liste de /128
            for router_index, router in enumerate(as_info['routers'], start=1):
                loopback_addr = loop_range.network_address + router_index
                self.ip_allocations[f"{asn_str}_{router}"] = {
                    'loopback': str(loopback_addr)
                }

            # Allocation des liens physiques (subnets /64 par exemple)
            all_subnets = list(phy_range.subnets(new_prefix=64))
            
            for link_counter, link in enumerate(as_info['topology']['links']):
                subnet = all_subnets[link_counter]
                link_id = f"{asn_str}_link_{link_counter}"
                self.ip_allocations[link_id] = {
                    'subnet': subnet,
                    'interfaces': {}
                }
                
                # Parcours des éléments du lien.
                # Exemple de lien intra-AS: ["R1:FastEthernet0/0", "R2:FastEthernet0/0"]
                # Exemple de lien inter-AS: ["R1:GigabitEthernet1/0", "R4:FastEthernet0/0", "interAS"]
                # On ignore le dernier élément "interAS" (s’il existe) pour l’adressage des interfaces
                is_inter_as = ('interAS' in link)
                
                # On crée un compteur local pour attribuer une IP unique à chaque interface
                host_index = 1
                for item in link:
                    if item == "interAS":
                        continue
                    router, iface = item.split(':')
                    # On donne l’adresse + host_index
                    address = subnet.network_address + host_index
                    self.ip_allocations[link_id]['interfaces'][f"{router}:{iface}"] = str(address)
                    host_index += 1



    def generate_router_config(self, asn, router):
        """Génère la configuration pour un routeur d'AS donné."""
        config = []
        # Ajouter le routage IPv6 globalement
        config.append("version 15.2")
        config.append("ipv6 unicast-routing")
        config.append("ipv6 cef")
        config.append("!")

        # Ajouter le hostname
        config.append(f"hostname {router}")
        
        # Récupération des infos sur l'AS
        as_info = next(a for a in self.data['ASes'] if a['asn'] == asn)

        # Stocker les interfaces déjà configurées pour éviter les doublons
        configured_interfaces = set()

        # Récupérer les interfaces réellement utilisées
        used_interfaces = {interface['name'] for interface in self.get_router_interfaces(asn, router)}

        # Configuration des interfaces utilisées
        for interface in self.get_router_interfaces(asn, router):
            iface_name = interface['name']
            ipv6_addr = interface['ipv6']
            
            if iface_name not in configured_interfaces:
                config.append(f"interface {iface_name}")
                config.append(f" no ip address")
                config.append(f" ipv6 address {ipv6_addr}")

                if iface_name.startswith("FastEthernet"):
                    config.append(" duplex full")  # FastEthernet doit être en full duplex
                elif iface_name.startswith("GigabitEthernet"):
                    config.append(" negotiation auto")  # GigabitEthernet ne supporte pas `duplex` et `speed`

                # Activation des interfaces utilisées
                if iface_name in used_interfaces:
                    config.append(" no shutdown")
                else:
                    config.append(" shutdown")

                # Activation de l'IGP si ce n'est pas une loopback
                if not iface_name.lower().startswith('loopback'):
                    if as_info['igp']['type'].upper() == 'RIP':
                        config.append(" ipv6 rip RIPng enable")
                    elif as_info['igp']['type'].upper() == 'OSPF':
                        config.append(" ipv6 ospf 1 area 0")

                config.append("!")  # Séparation entre chaque interface

                configured_interfaces.add(iface_name)  # Marquer l'interface comme configurée

        # Configuration IGP
        config += self.generate_igp_config(as_info, router)
        
        # Configuration BGP
        config += self.generate_bgp_config(as_info, router)

        config.append("end")
        
        return '\n'.join(config)




    def get_router_interfaces(self, asn, router):
        """Retourne toutes les interfaces du routeur avec leurs IPs (loopback + physiques)."""
        asn_str = str(asn)
        interfaces = []
        
        # Loopback0 : on récupère l'IP /128
        loopback_ip = self.ip_allocations[f"{asn_str}_{router}"]['loopback']
        interfaces.append({
            'name': 'Loopback0',
            'ipv6': f"{loopback_ip}/128"
        })
        
        # Interfaces physiques (dans self.ip_allocations qui contiennent "_link_")
        for link_id, link_data in self.ip_allocations.items():
            if not link_id.startswith(f"{asn_str}_link_"):
                continue
            for intf_key, ip_str in link_data['interfaces'].items():
                if intf_key.startswith(f"{router}:"):
                    interfaces.append({
                        'name': intf_key.split(':', maxsplit=1)[1],
                        'ipv6': f"{ip_str}/64"
                    })
        
        return interfaces


    def generate_igp_config(self, as_info, router):
        """Génère la configuration pour l'IGP (RIPng ou OSPFv3)."""
        config = []
        asn_str = str(as_info['asn'])
        
        igp_type = as_info['igp']['type'].upper()
        if igp_type == 'RIP':
            config.append("ipv6 router rip RIPng")
            config.append(" redistribute connected")
            config.append("!")
            # Pour chaque interface sauf Loopback0, on active RIPng
            for interface in self.get_router_interfaces(as_info['asn'], router):
                if interface['name'].lower().startswith("loopback"):
                    continue
                config.append(f"interface {interface['name']}")
                config.append(" ipv6 rip RIPng enable")
                config.append("!")
                
        elif igp_type == 'OSPF':
            config.append("ipv6 router ospf 1")
            # Construction du router-id à partir de la loopback (on prend juste la fin ou on fait un hash)
            # Pour simplifier, on prend l'adresse IPv6 et on met un dummy. Tu peux adapter.
            router_id = self.ip_allocations[f"{asn_str}_{router}"]['loopback']
            # Dans un vrai contexte on prendrait une IPv4 ou un int pour le router-id, 
            # ici on le simplifie grandement (tu peux parse la loopback et en faire un entier)
            config.append(f" router-id {self.router_id_from_loopback(router_id)}")
            config.append("!")
            # Activer OSPF sur chaque interface
            for interface in self.get_router_interfaces(as_info['asn'], router):
                config.append(f"interface {interface['name']}")
                config.append(" ipv6 ospf 1 area 0")
                config.append("!")
        return config

    def generate_bgp_config(self, as_info, router):
        """Génère la configuration BGP (iBGP + eBGP)."""
        config = []
        asn_str = str(as_info['asn'])
        loopback_ip = self.ip_allocations[f"{asn_str}_{router}"]['loopback']

        config.append(f"router bgp {as_info['asn']}")
        router_id = self.router_id_from_router_name(router)
        config.append(" no bgp default ipv4-unicast")
        config.append(f" bgp router-id {router_id}")
        config.append(" address-family ipv6 unicast")  # Utilisation d'IPv6

        networks_to_advertise = set()

        # Collecte des sous-réseaux à annoncer (loopback + interfaces physiques)
        for interface in self.get_router_interfaces(as_info['asn'], router):
            if interface['name'].lower().startswith('loopback'):
                networks_to_advertise.add(f"{interface['ipv6'].split('/')[0]}/128")
            else:
                ipv6_address = interface['ipv6'].split('/')[0]
                subnet = IPv6Network(ipv6_address + '/64', strict=False).network_address
                networks_to_advertise.add(str(subnet) + '/64')

        # Ajout des réseaux dans BGP
        for network in networks_to_advertise:
            config.append(f"  network {network}")

        # iBGP Peers (à l'intérieur de l'AS)
        if 'iBGPpeers' in as_info['routers'][router]['bgp']:
            for peer in as_info['routers'][router]['bgp']['iBGPpeers']:
                peer_loopback = self.ip_allocations[f"{asn_str}_{peer}"]['loopback']
                config.append(f"  neighbor {peer_loopback} remote-as {as_info['asn']}")
                config.append(f"  neighbor {peer_loopback} update-source Loopback0")
                config.append(f"  neighbor {peer_loopback} activate")

        # eBGP Peers (entre AS différents)
        if 'eBGPpeers' in as_info['routers'][router]['bgp']:
            for peer in as_info['routers'][router]['bgp']['eBGPpeers']:
                peer_as_info = next(a for a in self.data['ASes'] if peer in a['routers'])
                peer_asn = peer_as_info['asn']
                peer_ip = self.find_ebgp_peer_ip(as_info, peer_as_info, router, peer)
                config.append(f"  neighbor {peer_ip} remote-as {peer_asn}")
                config.append(f"  neighbor {peer_ip} activate")

        # Redistribution IGP
        if as_info['igp']['type'].upper() == 'RIP':
            config.append("  redistribute rip RIPng")
        elif as_info['igp']['type'].upper() == 'OSPF':
            config.append("  redistribute ospf 1")

        config.append(" exit-address-family")
        config.append("!")
        return config





    def router_id_from_router_name(self, router_name):
        """
        Assigne un router-id unique basé sur le nom du routeur.
        Exemple: R1 -> 1.1.1.1, R2 -> 2.2.2.2, etc.
        """
        try:
            num = int(router_name[1:])
            return f"{num}.{num}.{num}.{num}"
        except:
            return "1.1.1.1"  # Default si le nom ne correspond pas




    def find_ebgp_peer_ip(self, local_as_info, peer_as_info, local_router, peer_router):
        """
        Trouve l'adresse IPv6 du peer eBGP en se basant sur la topologie "interAS".
        """
        local_asn_str = str(local_as_info['asn'])
        peer_asn_str = str(peer_as_info['asn'])

        # Parcourir les liens de l'AS local
        for link_index, link in enumerate(local_as_info['topology']['links']):
            if 'interAS' in link:
                # Vérifier que les deux routeurs sont dans ce lien
                routers_in_link = [item for item in link if item != "interAS"]
                local_found = any(local_router == x.split(':')[0] for x in routers_in_link)
                peer_found = any(peer_router == x.split(':')[0] for x in routers_in_link)
                if local_found and peer_found:
                    link_id = f"{local_asn_str}_link_{link_index}"
                    # Trouver l'interface du peer
                    for intf_key, ip_str in self.ip_allocations[link_id]['interfaces'].items():
                        r_name, iface = intf_key.split(':', maxsplit=1)
                        if r_name == peer_router:
                            # Retourner l'adresse IPv6 sans le masque
                            return ip_str.split('/')[0]

        # Si aucun lien direct trouvé, retourner l'adresse Loopback du peer
        return self.ip_allocations[f"{peer_asn_str}_{peer_router}"]['loopback']





    def router_id_from_loopback(self, loopback_ip):
        """
        Convertit une IPv6 en un pseudo router-id IPv4 (ou un identifiant).
        Ici, on fait un hash très simpliste (dernier groupe hex) => transformé en decimal d'un int 32 bits max.
        À adapter à ta convenance.
        """
        # On coupe sur les :
        parts = loopback_ip.split(':')
        # On prend le dernier chunk
        last_chunk = parts[-1]
        # Si on a éventuellement un slash (ex: 2001:db8::1/128), on l'enlève
        last_chunk = last_chunk.split('/')[0]
        # On convertit de l'hex en int
        try:
            val = int(last_chunk, 16)
        except ValueError:
            val = 1
        # On ne garde que 32 bits
        val = val & 0xFFFFFFFF
        # On le remet en format "A.B.C.D"
        return "{}.{}.{}.{}".format(
            (val >> 24) & 0xFF,
            (val >> 16) & 0xFF,
            (val >> 8) & 0xFF,
            val & 0xFF
        )

# ========================================================================
#                            MAIN
# ========================================================================
if __name__ == "__main__":
    automator = NetworkAutomator('network_intent.json')
    
    # Pour chaque AS, pour chaque routeur, on génère un fichier de config
    for as_info in automator.data['ASes']:
        asn = as_info['asn']
        for router in as_info['routers']:
            config_str = automator.generate_router_config(asn, router)
            filename = f"{router}.cfg"
            with open(filename, "w") as f:
                f.write(config_str)
            print(f"Configuration générée pour {router} (AS {asn}) => {filename}")
