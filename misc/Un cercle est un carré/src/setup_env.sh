#!/bin/bash

# Nom du dossier de projet
PROJECT_DIR=~/FCSC2025/un_cercle

echo "📁 Création du dossier de travail : $PROJECT_DIR"
mkdir -p "$PROJECT_DIR"
cd "$PROJECT_DIR" || exit 1

echo "🐍 Création de l'environnement virtuel Python..."
python3 -m venv env || { echo "❌ Échec de création du venv"; exit 1; }

echo "✅ Environnement créé. Activation..."
source env/bin/activate || { echo "❌ Échec d'activation"; exit 1; }

echo "📦 Installation de NumPy..."
pip install --upgrade pip
pip install numpy || { echo "❌ Échec installation NumPy"; exit 1; }

echo "🧪 Vérification de l'installation..."
python -c "import numpy; print('[✅ NumPy installé]', numpy.__version__)"

echo "📥 Copie du script depuis /mnt/Share (si présent)..."
SRC_SCRIPT='/mnt/Share/FCSC2025/misc/Un cercle est un carré/carre_brute.py'
if [ -f "$SRC_SCRIPT" ]; then
    cp "$SRC_SCRIPT" ./carre_brute.py
    echo "✅ Script copié : carre_brute.py"
else
    echo "⚠️ Script introuvable à $SRC_SCRIPT"
fi

echo "🚀 Exécution possible avec :"
echo "    source env/bin/activate && python carre_brute.py"
