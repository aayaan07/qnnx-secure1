import os
import sys

def _initialize_liboqs_path():
    crypto_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.abspath(os.path.join(crypto_dir, '..', '..'))
    repo_candidates = (
        os.path.join(repo_root, 'libs', 'liboqs', 'build'),
        os.path.join(repo_root, 'libs', 'liboqs', 'install'),
        os.path.join(repo_root, 'liboqs', 'build'),
        os.path.join(repo_root, 'liboqs', 'install'),
        os.path.join(repo_root, '.oqs'),
    )
    active_root = next((candidate for candidate in repo_candidates if os.path.exists(candidate)), None)
    if not active_root:
        return

    os.environ["OQS_INSTALL_PATH"] = active_root
    print(f"--- DEBUG: Routing liboqs to {active_root} ---")

    if os.name == 'nt' and sys.version_info >= (3, 8):
        dll_search_paths = (
            os.path.join(active_root, 'bin'),
            os.path.join(active_root, 'bin', 'Debug'),
            os.path.join(active_root, 'bin', 'Release'),
        )

        for dll_path in dll_search_paths:
            try:
                if os.path.exists(dll_path):
                    os.add_dll_directory(dll_path)
                    print(f"--- DEBUG: Whitelisted DLL path: {dll_path} ---")
            except Exception as e:
                print(f"DEBUG: Failed to add DLL directory '{dll_path}': {e}")

# Run the initialization the moment the crypto module is imported
_initialize_liboqs_path()
