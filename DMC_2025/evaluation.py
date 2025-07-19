
import os
import subprocess

from tqdm import tqdm

ALG_LIST    = [
    "p256_falcon512", "p256_falcon512_kbl", "p256_falconpadded512", "p256_falconpadded512_kbl", 
    "p521_falcon1024", "p521_falcon1024_kbl", "p521_falconpadded1024", "p521_falconpadded1024_kbl",
    ]

for alg in ALG_LIST:
    os.makedirs(alg, exist_ok=True)

# Create directories for the signature schemes
print("Directories for signature schemes created successfully.")

N_ITERATION = 10  # Number of iterations

for alg in ALG_LIST:
    # Generate keys and certificates for each algorithm
    os.chdir(alg)
    print(f"[ {alg} ]\nGenerating keys and certificates...")

    for i in tqdm(range(N_ITERATION), desc=f"Generating {alg} keys and certs"):
        subprocess.run(f"openssl req -x509 -newkey {alg} -keyout {alg}_{i}_key.pem -out {alg}_{i}_cert.pem -days 365 -nodes -subj \"/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=example.com\"", 
                       shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"Keys and certificates generated for {alg} successfully.")
    
    # Delete key files after generation
    subprocess.run(f"rm {alg}_*_key.pem", shell=True)
    print(f"Key files deleted for {alg}.\n")
    # Change back to the parent directory
    os.chdir("..")

SIZE_LIST   = []
# Calculate the size of each certificate file
print("Calculating the size of each certificate file...")
for alg in ALG_LIST:
    tmp_size    = 0
    cert_list   = sorted(os.listdir(alg))
    for cert in tqdm(cert_list, desc=f"Calculating size for [ {alg} ]"):
        cert_size   = os.path.getsize(os.path.join(alg, cert))
        tmp_size    += cert_size
    SIZE_LIST.append(tmp_size / 1024)  # Convert to KB
print("Size calculation completed.\n")

print(SIZE_LIST)