# 🚀 Projet de Génération et Déploiement de Configurations Réseau

## 📌 Présentation du Projet

Ce projet automatise la **génération** et le **déploiement** de configurations pour des routeurs Cisco dans un environnement **GNS3**. Il repose sur un fichier d'intentions réseau (**intent.json**), contenant la description de l'architecture du réseau, pour produire automatiquement les fichiers de configuration des routeurs et les déployer dans un projet GNS3.

## 📂 Structure du Projet

```
📁 Projet_Réseau
│── 📜 generate_config.py  # Génère les configurations des routeurs
│── 📜 deploy_config.py    # Déploie les fichiers dans GNS3
│── 📜 network_intent.json # Fichier décrivant la topologie réseau
│── 📂 project-files/dynamips  # Répertoires des configurations GNS3
│── 📜 README.md          # Documentation du projet
```

---

## ⚙️ Fonctionnalités Principales

### ✅ **Génération Automatique des Configurations**
Le script `generate_config.py` génère les fichiers de configuration de chaque routeur à partir du fichier `network_intent.json`. Les fonctionnalités implémentées incluent :

- Attribution des adresses **IPv6** aux interfaces des routeurs.
- Configuration du **routage OSPFv3** (avec coût des liens).
- Génération des **relations BGP** (iBGP et eBGP).
- Gestion des **loopbacks** et **sous-réseaux inter-AS**.

### ✅ **Déploiement dans GNS3**
Le script `deploy_config.py` permet de remplacer les fichiers de configuration générés par ceux des routeurs dans GNS3. Il effectue :

- La détection des fichiers de configuration GNS3.
- La mise à jour des fichiers des routeurs dans le projet GNS3.
- L'affichage des remplacements effectués.

## 📌 Instructions d'Utilisation

### 1️⃣ **Installation des Dépendances**
Assurez-vous d'avoir **Python 3.7+** installé ainsi que les bibliothèques nécessaires :
```sh
pip install ipaddress
```

### 2️⃣ **Génération des Configurations**
Lancez le script `generate_config.py` pour générer les fichiers de configuration des routeurs :
```sh
python generate_config.py
```
Les fichiers `.cfg` seront générés dans le dossier du projet.

### 3️⃣ **Déploiement dans GNS3**
Lancez le script `deploy_config.py` pour copier les fichiers de configuration dans le projet GNS3 :
```sh
python deploy_config.py
```
Les fichiers de configuration des routeurs seront mis à jour dans **GNS3**.


## 🛠️ Personnalisation
Le fichier **network_intent.json** peut être modifié pour ajuster la topologie réseau et les configurations des routeurs.

## 💡 Points d'Amélioration
- Ajout de **politiques de routage avancées** (ex: route-maps BGP).
- Implémentation de **contrôles de cohérence** avant la génération des configurations.
- Support d'autres protocoles de routage (ex: **IS-IS**).

## 📝 Conclusion
Ce projet fournit une approche automatisée pour la configuration et le déploiement de routeurs dans un environnement **GNS3**, facilitant ainsi l'expérimentation et la simulation de réseaux complexes.
