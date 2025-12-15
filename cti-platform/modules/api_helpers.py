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

Helpers to standardize API responses
"""
import logging
from functools import wraps
from flask import jsonify
from typing import Any, Dict, Optional, Callable

logger = logging.getLogger(__name__)


def api_success(data: Optional[Dict] = None, message: Optional[str] = None, status_code: int = 200) -> tuple:
    """
    Returns a standardized API success response
    
    Args:
        data: Data to return
        message: Optional success message
        status_code: HTTP code (default: 200)
    
    Returns:
        Tuple (jsonify response, status_code)
    """
    response = {'success': True}
    if message:
        response['message'] = message
    if data:
        response.update(data)
    return jsonify(response), status_code


def api_error(error: str, status_code: int = 400, details: Optional[Dict] = None) -> tuple:
    """
    Returns a standardized API error response
    
    Args:
        error: Error message
        status_code: HTTP code (default: 400)
        details: Optional additional details
    
    Returns:
        Tuple (jsonify response, status_code)
    """
    response = {
        'success': False,
        'error': error
    }
    if details:
        response['details'] = details
    return jsonify(response), status_code


def api_not_found(resource: str = "Resource") -> tuple:
    """
    Returns a standardized API 404 response
    
    Args:
        resource: Name of the resource not found
    
    Returns:
        Tuple (jsonify response, 404)
    """
    return api_error(f"{resource} not found", 404)


def api_validation_error(errors: Dict[str, str]) -> tuple:
    """
    Returns a standardized API validation error response
    
    Args:
        errors: Dictionary of validation errors (field -> message)
    
    Returns:
        Tuple (jsonify response, 400)
    """
    return api_error("Validation error", 400, {'validation_errors': errors})


def handle_api_errors(route_name: str = None):
    """
    Decorator to automatically handle errors in API routes.
    Logs errors and returns a standardized API response.
    
    Usage:
        @app.route('/api/example')
        @handle_api_errors('api_example')
        def api_example():
            # Route code
            return api_success(...)
    
    Args:
        route_name: Route name for logging (optional, uses function name if not provided)
    """
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def wrapper(*args, **kwargs):
            try:
                return f(*args, **kwargs)
            except ValueError as e:
                route = route_name or f.__name__
                logger.warning(f"{route} validation error: {e}")
                return api_error(str(e), 400)
            except KeyError as e:
                route = route_name or f.__name__
                logger.warning(f"{route} missing key error: {e}")
                return api_error(f"Missing required field: {e}", 400)
            except PermissionError as e:
                route = route_name or f.__name__
                logger.warning(f"{route} permission error: {e}")
                return api_error("Permission denied", 403)
            except Exception as e:
                route = route_name or f.__name__
                logger.error(f"{route} error: {e}", exc_info=True)
                # Don't expose internal error details in production
                error_message = str(e) if logger.level <= logging.DEBUG else "An internal error occurred"
                return api_error(error_message, 500)
        return wrapper
    return decorator


class DatabaseError(Exception):
    """Standard database error exception"""
    pass


class ValidationError(Exception):
    """Standard validation error exception"""
    pass


class NotFoundError(Exception):
    """Standard not found error exception"""
    pass

