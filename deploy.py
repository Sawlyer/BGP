import os
import shutil
import glob

# Dossier contenant les fichiers générés
GENERATED_CONFIGS_DIR = os.getcwd()  # Si les fichiers sont dans le dossier courant

# Dossier GNS3 (change-le si besoin)
GNS3_PROJECT_DIR = os.path.join(os.getcwd(), "project-files", "dynamips")

# Mapping des routeurs vers leurs fichiers de config GNS3
def get_gns3_config_files():
    gns3_configs = {}
    
    # Lister les dossiers dans project-files/dynamips
    for uuid_dir in os.listdir(GNS3_PROJECT_DIR):
        uuid_path = os.path.join(GNS3_PROJECT_DIR, uuid_dir)
        if not os.path.isdir(uuid_path):
            continue
        
        configs_path = os.path.join(uuid_path, "configs")
        if not os.path.exists(configs_path):
            continue
        
        # Récupérer les fichiers de config (ex: i2_startup-config.cfg)
        for config_file in glob.glob(os.path.join(configs_path, "i*_startup-config.cfg")):
            router_id = os.path.basename(config_file).split("_")[0]  # Ex: i2
            gns3_configs[router_id] = config_file
    
    return gns3_configs

# Trouver et remplacer les fichiers de configuration
def replace_gns3_configs():
    gns3_configs = get_gns3_config_files()
    
    for router_cfg in os.listdir(GENERATED_CONFIGS_DIR):
        if not router_cfg.endswith(".cfg"):
            continue
        
        router_name = router_cfg.split(".")[0]  # Ex: R2
        router_id = f"i{router_name[1:]}"  # Transformer R2 -> i2
        
        if router_id in gns3_configs:
            destination_path = gns3_configs[router_id]
            source_path = os.path.join(GENERATED_CONFIGS_DIR, router_cfg)
            
            # Remplacement du fichier
            shutil.copy(source_path, destination_path)
            print(f"Remplacé : {destination_path} avec {source_path}")
        else:
            print(f"Aucune correspondance trouvée pour {router_name}")

if __name__ == "__main__":
    replace_gns3_configs()
