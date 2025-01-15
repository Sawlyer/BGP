import json
import os

# Compteurs globaux pour générer des adresses
g_link_index = 1
g_loop_index = 1

def allocate_link_subnet():
    """
    Retourne un /64 unique.
    Ex: "2001:db8:0:1::/64"
    """
    global g_link_index
    prefix = f"2001:db8:0:{g_link_index}::/64"
    g_link_index += 1
    return prefix

def allocate_loopback(router_name):
    """
    Retourne un /128 unique pour la loopback.
    Ex: "2001:db8:ffff:1::/128"
    """
    global g_loop_index
    loopaddr = f"2001:db8:ffff:{g_loop_index}::1/128"
    g_loop_index += 1
    return loopaddr

def find_router(as_list, router_name):
    """
    Retrouve le dictionnaire d'un routeur (nom = 'R1', etc.) dans un AS ou 
    dans la liste de tous les AS.
    """
    for as_info in as_list:
        for r in as_info["routers"]:
            if r["name"] == router_name:
                return r
    return None

def assign_addresses(intent_data):
    """
    Parcourt la structure JSON sans adresses et attribue dynamiquement :
      - un /64 par lien 
      - un /128 par loopback
    Puis remplit router["loopbacks"][...]["ipv6"] et interface["ipv6"].
    """
    # Liste de tous les routeurs, tous les AS confondus
    all_ases = intent_data["ASes"]

    # 1) Attribuer un /128 à chaque loopback
    for as_info in all_ases:
        for router in as_info["routers"]:
            for lo in router.get("loopbacks", []):
                lo_addr = allocate_loopback(router["name"])
                lo["ipv6"] = lo_addr

    # 2) Gérer les liens "connectedTo"
    #    On veut éviter de traiter deux fois (R1--R2) et (R2--R1)
    visited_links = set()

    for as_info in all_ases:
        for router in as_info["routers"]:
            rname = router["name"]
            for iface in router.get("interfaces", []):
                cto = iface.get("connectedTo")
                if not cto:
                    continue

                # cto est du type "R2:FastEthernet0/0"
                peer_r, peer_i = cto.split(":")

                # On crée une clé unique (router,iface,peer_r,peer_i) dans un ordre déterministe
                link_key = tuple(sorted([
                    (rname, iface["name"]),
                    (peer_r, peer_i)
                ]))

                if link_key in visited_links:
                    # Ce lien est déjà traité
                    continue

                # Allouer un /64
                subnet64 = allocate_link_subnet()  # ex "2001:db8:0:1::/64"
                # On va remplacer "::/64" par "::1/64" pour un côté, "::2/64" pour l'autre
                ip1 = subnet64.replace("::/64", "::1/64")
                ip2 = subnet64.replace("::/64", "::2/64")

                # Assigner ip1 à (rname, iface)
                iface["ipv6"] = ip1

                # Trouver le routeur peer, l'interface peer
                peer_router = find_router(all_ases, peer_r)
                if peer_router:
                    for piface in peer_router.get("interfaces", []):
                        if piface["name"] == peer_i:
                            piface["ipv6"] = ip2
                            break

                visited_links.add(link_key)

    return intent_data

def generate_cisco_config(router_data, as_number, igp):
    """
    Génère la configuration Cisco IOS pour un routeur donné
    (après que les IPv6 aient été attribuées).
    """
    config_lines = []

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
        name = lo["name"]       # e.g. "Loopback0"
        ipv6 = lo["ipv6"]       # ex "2001:db8:ffff:1::1/128"

        config_lines.append(f"interface {name}")
        config_lines.append(" no ip address")
        config_lines.append(f" ipv6 address {ipv6}")

        # Activer IGP sur la loopback si souhaité
        if igp == "RIP":
            config_lines.append(f" ipv6 rip RIP_{as_number} enable")
        elif igp == "OSPF":
            config_lines.append(f" ipv6 ospf 1 area 0")

        config_lines.append("!")
    
    # --- INTERFACES PHYSIQUES ---
    for iface in router_data.get("interfaces", []):
        name = iface["name"]
        ipv6 = iface.get("ipv6", None)  # Peut être défini par assign_addresses
        desc = iface.get("description", "")
        igp_enabled = iface.get("igpEnabled", False)

        config_lines.append(f"interface {name}")
        config_lines.append(" no ip address")

        # Sur du FastEthernet, on met "duplex full"; sur du GigabitEthernet, "negotiation auto"
        if name.startswith("FastEthernet"):
            config_lines.append(" duplex full")
        else:
            config_lines.append(" negotiation auto")

        if ipv6:
            config_lines.append(f" ipv6 address {ipv6}")

        if desc:
            config_lines.append(f" description {desc}")

        if igp_enabled:
            if igp == "RIP":
                config_lines.append(f" ipv6 rip RIP_{as_number} enable")
            elif igp == "OSPF":
                config_lines.append(f" ipv6 ospf 1 area 0")

        config_lines.append("!")

    # --- ROUTER IGP ---
    if igp == "RIP":
        config_lines.append(f"ipv6 router rip RIP_{as_number}")
        config_lines.append(" redistribute connected")
        config_lines.append("!")
    elif igp == "OSPF":
        # OSPF classique + redistribution
        config_lines.append("router ospf 1")
        config_lines.append(f" router-id {router_data['routerID']}")
        config_lines.append(f" redistribute bgp {as_number} subnets")
        config_lines.append("!")
        config_lines.append("ipv6 router ospf 1")
        config_lines.append(f" router-id {router_data['routerID']}")
        config_lines.append(" redistribute connected")
        config_lines.append("!")

    # --- ROUTER BGP ---
    config_lines.append(f"router bgp {as_number}")
    config_lines.append(f" bgp router-id {router_data['routerID']}")
    config_lines.append(" bgp log-neighbor-changes")
    config_lines.append(" no bgp default ipv4-unicast")

    # Famille IPv4 (optionnel)
    config_lines.append(" address-family ipv4")
    config_lines.append(" exit-address-family")
    config_lines.append(" !")

    # Famille IPv6
    config_lines.append(" address-family ipv6")

    # Redistribuer l'IGP dans BGP
    if igp == "RIP":
        config_lines.append(f"  redistribute rip RIP_{as_number}")
    elif igp == "OSPF":
        config_lines.append("  redistribute ospf 1")

    # On peut injecter les loopbacks/interfaces en "network" si on veut
    # (ici, on laisse la redistribution faire le job, ou on pourrait boucler).
    # Au besoin, décommenter si vous souhaitez des 'network' explicites.

    # BGP neighbors
    for neigh in router_data.get("bgpNeighbors", []):
        remote_as = neigh["remoteAs"]
        relationship = neigh["relationship"].lower()  # 'ibgp' ou 'ebgp'

        # Trouver l'adresse voisine
        # Si iBGP => on prend la loopback du voisin
        # Si eBGP => on prend l'adresse d'interface
        neighbor_ip = None

        if relationship == "ibgp" and (remote_as == as_number):
            # On va chercher la loopback du voisin
            # NB: On suppose qu'il a "loopbacks"[0]["ipv6"]
            #    Dans l'idéal, on chercherait la 1ère loopback
            # => On ne sait pas ici le nom du voisin, donc on doit le retouver dans l'intent
            #    ou on stocke un mapping global "routerName -> loopbacks[0].ipv6"
            #    Par simplicité, on suppose qu'on l'a fait plus tôt
            pass
        else:
            # eBGP => on prend l'adresse d'interface du voisin
            # on a besoin de parser la config voisine
            pass

        # TEMP: Pour l'exemple, on va juste mettre un placeholder "FE80::1"
        # Dans la vraie vie, il faut un mapping routeur -> IP
        # => c'est plus complexe qu'une simple boucle ici
        # => on te laisse implémenter la recherche de la "good IP"

        # Juste un placeholder par défaut
        neighbor_ip = f"FE80::{remote_as}"  # obviously a dummy IP

        config_lines.append(f"  neighbor {neighbor_ip} remote-as {remote_as}")
        config_lines.append("  neighbor {0} activate".format(neighbor_ip))

        # Si iBGP => update-source Loopback0
        if relationship == "ibgp" and (remote_as == as_number):
            config_lines.append(f"  neighbor {neighbor_ip} update-source Loopback0")

    config_lines.append(" exit-address-family")
    config_lines.append("!")

    # Fin de la config standard
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

    return "\n".join(config_lines)


def main():
    intent_file = "my_intent.json"  # Nom de fichier d'intention
    with open(intent_file, "r") as f:
        intent_data = json.load(f)

    # 1) On attribue dynamiquement les adresses
    intent_data = assign_addresses(intent_data)

    # 2) On crée un dossier de sortie
    output_dir = "configs"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # 3) On génère les configs
    for as_info in intent_data["ASes"]:
        asn = as_info["asn"]
        igp = as_info["igp"]
        for router_data in as_info["routers"]:
            router_name = router_data["name"]

            config_str = generate_cisco_config(router_data, asn, igp)

            # Fichier de sortie
            out_filename = f"{router_name}_config.txt"
            out_path = os.path.join(output_dir, out_filename)
            with open(out_path, "w") as outfile:
                outfile.write(config_str)

            print(f"[OK] Généré : {out_filename}")

if __name__ == "__main__":
    main()
