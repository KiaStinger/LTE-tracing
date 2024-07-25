import subprocess
import platform
from tqdm import tqdm

def main():
    list_of_lines = reading()
    parsed_base = parse_lines(list_of_lines)
    result_dict = create_result_dict(parsed_base)
    traceroute_between_ips(result_dict)
    return 0


def reading():
    with open("http.txt", "r") as file:
        lines = file.readlines()
    return lines


def parse_lines(some_list):
    some_dict = {'first_IP': [], 'second_IP': [], 'ports': [], 'protocols': []}
    for line in some_list:
        parts = line.split()
        some_dict['first_IP'].append(parts[0])
        some_dict['second_IP'].append(parts[1])
        some_dict['ports'].append(parts[2])
        some_dict['protocols'].append(parts[3])
    return some_dict


def create_result_dict(parsed_data):
    result_dict = {}
    for i, first_ip in enumerate(parsed_data['first_IP']):
        second_ip = parsed_data['second_IP'][i]
        if first_ip in result_dict:
            if second_ip not in result_dict[first_ip]:
                result_dict[first_ip].append(second_ip)
        else:
            result_dict[first_ip] = [second_ip]
    return result_dict


def traceroute_between_ips(result_dict):
    traced_pairs = set()
    with open("graph.dot", "w") as dot_file, open("statistics.txt", "w") as statistics_file:
        dot_file.write('strict graph traceroute {\n')
        statistics_file.write("From_IP\tTo_IP\tHop\tIP\tRTT\tAS\n")
        for first_ip, second_ips in result_dict.items():
            for second_ip in tqdm(second_ips, desc="Tracing Routes"):
                ip_pair = tuple(sorted([first_ip, second_ip]))
                if ip_pair not in traced_pairs:
                    if platform.system() == "Windows":
                        traceroute_command = ["tracert", "-d", "-h", "32", second_ip]
                    else:
                        traceroute_command = ["traceroute", "-n", "-m", "32", second_ip]

                    try:
                        traceroute_output = subprocess.check_output(traceroute_command, universal_newlines=True)
                        hops = traceroute_output.strip().split('\n')[1:-1]
                        write_to_dot_file(dot_file, first_ip, second_ip, hops)
                        write_to_statistics_file(statistics_file, first_ip, second_ip, hops)
                        traced_pairs.add(ip_pair)
                    except subprocess.CalledProcessError as e:
                        print(f"Error executing traceroute: {e}")

        dot_file.write("}\n")


def write_to_dot_file(dot_file, from_ip, to_ip, hops):
    dot_file.write(f'\tsubgraph cluster_{from_ip.replace(".", "_")}_{to_ip.replace(".", "_")} {{\n')
    dot_file.write(f'\t\tlabel="{from_ip} -- {to_ip}"\n')
    prev_hop_ip = from_ip
    for hop in hops:
        hop_parts = hop.split()
        if len(hop_parts) > 2 and hop_parts[1] != '***':
            hop_ip = hop_parts[1].strip('()')
            if hop_ip == '*' or prev_hop_ip == '*':
                continue
            dot_file.write(f'\t\t"{prev_hop_ip}" -- "{hop_ip}"\n')
            prev_hop_ip = hop_ip
    dot_file.write(f'\t\t"{prev_hop_ip}" -- "{to_ip}"\n')
    dot_file.write(f'\t}}\n')

def write_to_statistics_file(statistics_file, from_ip, to_ip, hops):
    for i, hop in enumerate(hops, 1):
        hop_parts = hop.split()
        if len(hop_parts) > 2 and hop_parts[1] != '***':
            hop_ip = hop_parts[1].strip('()')
            rtt = hop_parts[2]
            as_number = get_as_number(hop_ip)
            statistics_file.write(f"{from_ip:<14}\t{to_ip:<14}\t{i:<14}\t{hop_ip:<14}\t{rtt:<14}\t{as_number:<14}\n")
    statistics_file.write("\n" + "_"*90 + "\n\n")

def get_as_number(ip):
    try:
        whois_output = subprocess.check_output(["whois", ip], universal_newlines=True)
        for line in whois_output.split("\n"):
            if "origin" in line.lower() and "as" in line.lower():
                as_number = line.split()[-1]
                return as_number
    except subprocess.CalledProcessError as e:
        print(f"Error executing whois: {e}")
    return "AS_UNKNOWN"


if __name__ == "__main__":
    main()

