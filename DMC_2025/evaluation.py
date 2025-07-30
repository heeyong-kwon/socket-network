
import os
import subprocess
import time

from tqdm import tqdm

# ALG_LIST    = [
#     "p256_falcon512", "p256_falcon512_kbl", "p256_falconpadded512", "p256_falconpadded512_kbl", 
#     "p521_falcon1024", "p521_falcon1024_kbl", "p521_falconpadded1024", "p521_falconpadded1024_kbl",
#     ]

ALG_LIST    = [
    "p256_falconpadded512", "p256_falconpadded512_kbl", 
    "p521_falconpadded1024", "p521_falconpadded1024_kbl",
    ]

N_ITERATION = 1000    # Number of iterations

# # Experiments for signature
# lst_sig_time    = []
# lst_sig_size    = []
# for alg in ALG_LIST:
#     # Generate key for sign
#     os.system(f"openssl genpkey -algorithm {alg} -out {alg}.key")
#     # os.system(f"openssl pkey -in {alg}.key -pubout -out {alg}.pub")
#     t_total = 0
#     s_total = 0
#     for _ in tqdm(range(N_ITERATION), desc=f"Generation {alg} signature"):
#         t_start = time.time()
#         os.system(f"openssl pkeyutl -sign -inkey {alg}.key -in msg.txt -out sig.bin")
#         t_end   = time.time()
#         t_total += (t_end - t_start)
#         with open("sig.bin", "rb") as f:
#             sig = f.read()
#             s_total += len(sig)
#     lst_sig_time.append(t_total)
#     lst_sig_size.append(s_total)

# idx = 0
# for alg in ALG_LIST:
#     print(f"Average Time for {alg.ljust(25, ' ')}\t:{lst_sig_time[idx] / N_ITERATION}")
#     idx += 1
# print()
# idx = 0
# for alg in ALG_LIST:
#     print(f"Average Size for {alg.ljust(25, ' ')}\t:{lst_sig_size[idx] / N_ITERATION}")
#     idx += 1



# Experiments for digital certificate
for alg in ALG_LIST:
    os.makedirs(alg, exist_ok=True)

# Create directories for the signature schemes
print("Directories for signature schemes created successfully.")

lst_cert_time   = []
for alg in ALG_LIST:
    # Generate keys and certificates for each algorithm
    os.chdir(alg)
    print(f"[ {alg} ]\nGenerating keys and certificates...")

    t_total = 0
    for i in tqdm(range(N_ITERATION), desc=f"Generating {alg} keys and certs"):
        t_start = time.time()
        subprocess.run(f"openssl req -x509 -newkey {alg} -keyout {alg}_{i}_key.pem -out {alg}_{i}_cert.pem -days 365 -nodes -subj \"/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=example.com\"", 
                       shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        t_end   = time.time()
        t_total += (t_end - t_start)
    lst_cert_time.append(t_total)
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
    # SIZE_LIST.append(tmp_size / 1024)  # Convert to KB
    SIZE_LIST.append(tmp_size)
print("Size calculation completed.\n")


idx = 0
for alg in ALG_LIST:
    print(f"Average Time for {alg.ljust(25, ' ')}\t:{lst_cert_time[idx] / N_ITERATION}")
    idx += 1
print()

idx = 0
for alg in ALG_LIST:
    print(f"Average Size for {alg.ljust(25, ' ')}\t:{SIZE_LIST[idx] / N_ITERATION}")
    idx += 1
print()