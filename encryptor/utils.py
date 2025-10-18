import os

def get_all_user_profiles():
    users_path = os.path.join(os.getenv("SystemDrive", "C:"), r"\Users")
    excluded_users = {'Default', 'Default User', 'Public', 'All Users', 'WsiAccount'}
    
    user_list = []
    if not os.path.exists(users_path):
        return []

    for user_name in os.listdir(users_path):
        user_profile_path = os.path.join(users_path, user_name)
        if os.path.isdir(user_profile_path) and \
           user_name not in excluded_users and \
           os.path.exists(os.path.join(user_profile_path, "Desktop")):
            user_list.append(user_name)
    return user_list