import click
import getpass
import sys
from typing import Optional
from pathlib import Path
import os
from src.models.user import User, UserRole
from src.services.artifact_service import ArtifactService
from src.utils.logging import AuditLogger
from src.auth.rbac import RBACManager

class CLI:
    def __init__(self):
        self.artifact_service = ArtifactService()
        self.rbac_manager = RBACManager()
        self.logger = AuditLogger()
        self.current_user: Optional[User] = None
        
    def login(self) -> bool:
        """Handle user login"""
        username = input("Username: ")
        password = getpass.getpass("Password: ")
        
        user = self.rbac_manager.authenticate(username, password)
        if user:
            self.current_user = user
            self.logger.log_auth_attempt(username, True, "127.0.0.1")
            return True
            
        self.logger.log_auth_attempt(username, False, "127.0.0.1")
        return False
        
    def require_auth(self):
        """Check if user is authenticated"""
        if not self.current_user:
            print("Please login first")
            sys.exit(1)

@click.group()
@click.pass_context
def main(ctx):
    """Secure Digital Copyright Management CLI"""
    ctx.obj = CLI()

@main.command()
@click.pass_obj
def login(cli: CLI):
    """Login to the system"""
    if cli.login():
        print("Login successful")
    else:
        print("Login failed")
        sys.exit(1)

@main.command()
@click.argument('file', type=click.Path(exists=True))
@click.option('--name', prompt=True)
@click.option('--type', 'content_type', prompt=True, 
              type=click.Choice(['lyrics', 'score', 'audio']))
@click.pass_obj
def upload(cli: CLI, file: str, name: str, content_type: str):
    """Upload a new artifact"""
    cli.require_auth()
    
    try:
        with open(file, 'rb') as f:
            content = f.read()
            
        artifact_id = cli.artifact_service.create_artifact(
            cli.current_user,
            name,
            content_type,
            content
        )
        
        if artifact_id:
            print(f"Artifact created with ID: {artifact_id}")
        else:
            print("Failed to create artifact")
            sys.exit(1)
            
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

@main.command()
@click.argument('artifact_id')
@click.argument('output', type=click.Path())
@click.pass_obj
def download(cli: CLI, artifact_id: str, output: str):
    """Download an artifact"""
    cli.require_auth()
    
    try:
        content = cli.artifact_service.read_artifact(
            cli.current_user,
            artifact_id
        )
        
        if content:
            with open(output, 'wb') as f:
                f.write(content)
            print(f"Artifact saved to: {output}")
        else:
            print("Failed to read artifact")
            sys.exit(1)
            
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

@main.command()
@click.pass_obj
def list(cli: CLI):
    """List available artifacts"""
    cli.require_auth()
    
    artifacts = cli.artifact_service.list_artifacts(cli.current_user)
    if not artifacts:
        print("No artifacts found")
        return
        
    for artifact in artifacts:
        print(f"\nID: {artifact['id']}")
        print(f"Name: {artifact['name']}")
        print(f"Type: {artifact['content_type']}")
        print(f"Created: {artifact['created_at']}")
        
if __name__ == '__main__':
    main() 