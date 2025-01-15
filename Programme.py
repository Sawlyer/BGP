import json
import os

def generate_cisco_config(router_data, as_number, igp):
    """
    Génère la configuration Cisco IOS pour un routeur donné,
    à partir des infos du JSON (router_data), du n° d'AS (as_number) et de l'IGP (igp).
    """
    config_lines = []

    # Préambule standard
    config_lines.append("!")
    config_lines.append("version 15.2")
    config_lines.append("service timestamps debug datetime msec")
    config_lines.append("service timestamps log datetime msec")
    config_lines.append("!")
    config_lines.append(f"hostname {router_data['hostname']}")
    config_lines.append("!")
    config_lines.append("no ip domain-lookup")
    config_lines.append("ipv6 unicast-routing")
    config_lines.append("ipv6 cef")
    config_lines.append("!")
    config_lines.append("multilink bundle-name authenticated")
    config_lines.append("!")
    config_lines.append("ip tcp synwait-time 5")
    config_lines.append("!")
    
    # --- INTERFACES LOOPBACK ---
    for lo in router_data.get("loopbacks", []):
        name = lo["name"]                # e.g. "Loopback0"
        ipv6 = lo["ipv6"]                # e.g. "2001:1:1::1/128"

        config_lines.append(f"interface {name}")
        config_lines.append(" no ip address")
        config_lines.append(f" ipv6 address {ipv6}")

        # Activer l'IGP si besoin
        if igp == "RIP":
            # On peut donner un nom au process RIP (ex: RIP_X) basé sur l'AS
            config_lines.append(f" ipv6 rip RIP_{as_number} enable")
        elif igp == "OSPF":
            config_lines.append(f" ipv6 ospf 1 area 0")
        config_lines.append("!")
    
    # --- INTERFACES PHYSIQUES ---
    for iface in router_data.get("interfaces", []):
        name = iface["name"]             # e.g. "FastEthernet0/0"
        ipv6 = iface["ipv6"]             # e.g. "2001:1:12::1/64"
        desc = iface.get("description", "")
        igp_enabled = iface.get("igpEnabled", False)

        config_lines.append(f"interface {name}")
        config_lines.append(" no ip address")
        # Pour c7200, certains interfaces nécessitent "duplex full" ou "negotiation auto".
        # On peut détecter si c'est FastEthernet ou GigabitEthernet, et ajouter la commande ad-hoc.
        if name.startswith("FastEthernet"):
            config_lines.append(" duplex full")
        else:
            config_lines.append(" negotiation auto")

        config_lines.append(f" ipv6 address {ipv6}")
        if desc:
            config_lines.append(f" description {desc}")

        # Activer l'IGP sur cette interface si igpEnabled = true
        if igp_enabled:
            if igp == "RIP":
                config_lines.append(f" ipv6 rip RIP_{as_number} enable")
            elif igp == "OSPF":
                config_lines.append(f" ipv6 ospf 1 area 0")
        config_lines.append("!")
    
    # --- ROUTER IGP ---
    if igp == "RIP":
        config_lines.append(f"ipv6 router rip RIP_{as_number}")
        # On peut éventuellement redistribuer connected ou statics
        config_lines.append(" redistribute connected")
        config_lines.append("!")
    elif igp == "OSPF":
        config_lines.append("router ospf 1")
        config_lines.append(f" router-id {router_data['routerID']}")
        # Redistribuer BGP si on veut
        config_lines.append(f" redistribute bgp {as_number} subnets")
        config_lines.append("!")
        config_lines.append(f"ipv6 router ospf 1")
        config_lines.append(f" router-id {router_data['routerID']}")
        config_lines.append(" redistribute connected")
        config_lines.append("!")
    
    # --- ROUTER BGP ---
    config_lines.append(f"router bgp {as_number}")
    config_lines.append(f" bgp router-id {router_data['routerID']}")
    config_lines.append(" bgp log-neighbor-changes")
    config_lines.append(" no bgp default ipv4-unicast")

    # On active la famille ipv4 (même si tu ne l'utilises pas, c'est souvent standard)
    config_lines.append(" address-family ipv4")
    config_lines.append(" exit-address-family")
    config_lines.append(" !")

    config_lines.append(" address-family ipv6")
    # Exemple : si on veut redistribuer l'IGP vers BGP
    if igp == "RIP":
        config_lines.append(f"  redistribute rip RIP_{as_number}")
    elif igp == "OSPF":
        config_lines.append("  redistribute ospf 1")

    # On peut ajouter des network ... (ex: pour loopbacks + liaisons)
    # Dans ton exemple, tu mets explicitement network 2001:1:1::/64, etc.
    # On peut boucler sur les interfaces/loopbacks pour injecter "network".
    # Ci-dessous un simple exemple:
    #------------------------------------
    # 1) Injections des loopbacks 
    for lo in router_data.get("loopbacks", []):
        # On découpe l'adresse pour /64 par ex. Mais dans ton exemple,
        # tu as parfois mis network <préfixe> + /64. A toi d'adapter.
        # On va supposer que c'est un /128 => on annonce le /128 lui-même
        netaddr = lo["ipv6"].split('/')[0]  # "2001:1:1::1"
        prefixlen = lo["ipv6"].split('/')[1]  # "128"
        # Pour injecter un /128, on peut le faire en "network <ip>/128"
        config_lines.append(f"  network {netaddr}/{prefixlen}")

    # 2) Injections des interfaces
    for iface in router_data.get("interfaces", []):
        netaddr = iface["ipv6"].split('/')[0]
        prefixlen = iface["ipv6"].split('/')[1]
        # On peut supposer que c'est du /64
        config_lines.append(f"  network {netaddr}::/{prefixlen}")
    #------------------------------------

    # BGP Neighbors
    for neigh in router_data.get("bgpNeighbors", []):
        neighbor_ip = neigh["neighborIPv6"]
        remote_as = neigh["remoteAs"]
        config_lines.append(f"  neighbor {neighbor_ip} remote-as {remote_as}")
        config_lines.append(f"  neighbor {neighbor_ip} activate")
        # Si iBGP => update-source Loopback0 (ebgp = false)
        if not neigh["ebgp"] and (remote_as == as_number):
            config_lines.append(f"  neighbor {neighbor_ip} update-source Loopback0")

    config_lines.append(" exit-address-family")
    config_lines.append("!")

    # Fin de config: accès, lines, etc.
    config_lines.append("ip forward-protocol nd")
    config_lines.append("no ip http server")
    config_lines.append("no ip http secure-server")
    config_lines.append("!")
    config_lines.append("control-plane")
    config_lines.append("!")
    config_lines.append("line con 0")
    config_lines.append(" exec-timeout 0 0")
    config_lines.append(" privilege level 15")
    config_lines.append(" logging synchronous")
    config_lines.append(" stopbits 1")
    config_lines.append("line aux 0")
    config_lines.append(" exec-timeout 0 0")
    config_lines.append(" privilege level 15")
    config_lines.append(" logging synchronous")
    config_lines.append(" stopbits 1")
    config_lines.append("line vty 0 4")
    config_lines.append(" login")
    config_lines.append("!")
    config_lines.append("end")
    config_lines.append("")

    # On retourne la config sous forme de string
    return "\n".join(config_lines)


def main():
    # Nom du fichier JSON d'intent
    intent_file = "my_intent.json"

    # Chargement du JSON
    with open(intent_file, "r") as f:
        intent_data = json.load(f)

    network_name = intent_data.get("networkName", "MyNetwork")

    # Créer un dossier de sortie (ex : "configs") si besoin
    output_dir = "configs"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Pour chaque AS
    for as_info in intent_data["ASes"]:
        asn = as_info["asn"]       # e.g. 65001
        igp = as_info["igp"]       # e.g. "RIP" ou "OSPF"

        # Pour chaque routeur
        for router_data in as_info["routers"]:
            router_name = router_data["name"]  # e.g. "R1"
            # Générer la config
            config_str = generate_cisco_config(router_data, asn, igp)

            # Nom de fichier : R1_config.txt, R2_config.txt, etc.
            out_filename = f"{router_name}_config.txt"
            out_path = os.path.join(output_dir, out_filename)
            
            # Écrire le fichier
            with open(out_path, "w") as outfile:
                outfile.write(config_str)
            
            print(f"Config générée pour {router_name} -> {out_path}")


if __name__ == "__main__":
    main()
