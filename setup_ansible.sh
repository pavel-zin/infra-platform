python -m venv .venv_ansible

source .venv_ansible/bin/activate

pip install ansible ansible-lint

ansible-galaxy collection install -r requirements.yml
