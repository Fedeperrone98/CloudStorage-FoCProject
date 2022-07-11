# 1. COMPILAZIONE
  make

  read -p "Compilazione eseguita. Premi invio per eseguire..."

# 2. ESECUZIONE

# 2.1 esecuzioe del server sulla porta 4242
  gnome-terminal -x sh -c "./server 4242; exec bash"

# 2.2 esecuzione del client sulla porta
  gnome-terminal -x sh -c "./client 5001; exec bash"