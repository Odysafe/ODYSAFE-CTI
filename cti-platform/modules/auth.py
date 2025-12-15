"""
Odysafe CTI Platform
Copyright (C) 2025 Bastien GUIDONE

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

Module d'authentification pour CTI Platform
"""
import logging
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask import session, redirect, url_for, request

logger = logging.getLogger(__name__)


def is_auth_enabled(db) -> bool:
    """Vérifie si l'authentification est activée"""
    try:
        auth_enabled = db.get_setting('auth_enabled', 'false')
        return auth_enabled.lower() == 'true'
    except Exception as e:
        logger.error(f"Error checking auth status: {e}")
        return False


def require_auth(f):
    """Décorateur pour protéger les routes nécessitant une authentification"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Utiliser l'instance globale db depuis app.py via flask.g
        from flask import g
        if not hasattr(g, 'db'):
            # Si pas d'instance dans g, créer une nouvelle (fallback)
            from database import Database
            g.db = Database()
        
        # Si l'auth n'est pas activée, pas besoin d'authentification
        if not is_auth_enabled(g.db):
            return f(*args, **kwargs)
        
        # Si l'utilisateur n'est pas connecté, rediriger vers login
        if 'user_id' not in session:
            if request.is_json or request.path.startswith('/api/'):
                from modules.api_helpers import api_error
                return api_error("Authentication required", 401)
            return redirect(url_for('login'))
        
        return f(*args, **kwargs)
    return decorated_function


def create_user(db, username: str, password: str) -> tuple[bool, str]:
    """
    Crée un nouvel utilisateur
    
    Args:
        db: Instance de Database
        username: Nom d'utilisateur
        password: Mot de passe en clair
    
    Returns:
        Tuple (success: bool, message: str)
    """
    try:
        with db.connection() as conn:
            ody = conn.cursor()
            ody.execute("SELECT id FROM users WHERE username = ?", (username,))
            if ody.fetchone():
                return False, "Username already exists"
            
            # Créer le hash du mot de passe
            password_hash = generate_password_hash(password)
            
            # Insérer l'utilisateur
            ody.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash)
            )
        
        logger.info(f"User '{username}' created successfully")
        return True, "User created successfully"
    
    except Exception as e:
        logger.error(f"Error creating user: {e}")
        return False, f"Error creating user: {str(e)}"


def verify_user(db, username: str, password: str) -> tuple[bool, str]:
    """
    Vérifie les identifiants d'un utilisateur
    
    Args:
        db: Instance de Database
        username: Nom d'utilisateur
        password: Mot de passe en clair
    
    Returns:
        Tuple (success: bool, message: str)
    """
    try:
        with db.connection() as conn:
            ody = conn.cursor()
            ody.execute(
                "SELECT id, password_hash FROM users WHERE username = ?",
                (username,)
            )
            user = ody.fetchone()
        
        if not user:
            return False, "Invalid username or password"
        
        user_id, password_hash = user
        
        # Vérifier le mot de passe
        if check_password_hash(password_hash, password):
            return True, str(user_id)
        else:
            return False, "Invalid username or password"
    
    except Exception as e:
        logger.error(f"Error verifying user: {e}")
        return False, f"Error verifying user: {str(e)}"


def change_password(db, username: str, old_password: str, new_password: str) -> tuple[bool, str]:
    """
    Change le mot de passe d'un utilisateur
    
    Args:
        db: Instance de Database
        username: Nom d'utilisateur
        old_password: Ancien mot de passe
        new_password: Nouveau mot de passe
    
    Returns:
        Tuple (success: bool, message: str)
    """
    try:
        # Vérifier l'ancien mot de passe
        success, result = verify_user(db, username, old_password)
        if not success:
            return False, "Current password is incorrect"
        
        # Générer le nouveau hash
        new_password_hash = generate_password_hash(new_password)
        
        # Mettre à jour le mot de passe
        with db.connection() as conn:
            ody = conn.cursor()
            ody.execute(
                "UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE username = ?",
                (new_password_hash, username)
            )
        
        logger.info(f"Password changed for user '{username}'")
        return True, "Password changed successfully"
    
    except Exception as e:
        logger.error(f"Error changing password: {e}")
        return False, f"Error changing password: {str(e)}"


def user_exists(db, username: str) -> bool:
    """Vérifie si un utilisateur existe"""
    try:
        with db.connection() as conn:
            ody = conn.cursor()
            ody.execute("SELECT id FROM users WHERE username = ?", (username,))
            exists = ody.fetchone() is not None
        return exists
    except Exception as e:
        logger.error(f"Error checking user existence: {e}")
        return False


def get_current_username() -> str | None:
    """Récupère le nom d'utilisateur de la session actuelle"""
    return session.get('username')

