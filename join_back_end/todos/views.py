from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from .models import TodoItem, Contact, UserToken
from rest_framework import status
from .serializers import TodoItemSerializer, ContactSerializer, UserSerializer, UserTokenSerializer, LoginSerializer
from django.shortcuts import get_object_or_404
from django.contrib.auth import authenticate, login, logout
from rest_framework.permissions import IsAuthenticated
from rest_framework.authtoken.models import Token
from django.contrib.auth.models import User

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token
from .serializers import UserSerializer

class LoginView(APIView):
    """
    API View for user login.

    This view handles user login by verifying a token and checking user credentials.
    If the token and credentials are valid, the user is logged in and their details are returned.
    
    Methods:
        - post: Handles the login process, including token validation, credential checks, and user authentication.

    HTTP Methods:
        - POST: Logs the user in based on provided email and password.
    """

    def post(self, request, format=None):
        """
        Handles the POST request for user login.

        This method validates the provided token and user credentials (email and password).
        If the token is valid and the credentials match, the user is logged in and their
        details are returned.

        Args:
            request: The HTTP request containing the token, email, and password.
            format: The format of the request (optional).

        Returns:
            Response: JSON response containing user details on successful login or
                      an error message on failure.

        Raises:
            HTTP_400_BAD_REQUEST: If the token, email, or password is missing.
            HTTP_401_UNAUTHORIZED: If the token is invalid or the credentials are incorrect.
            HTTP_404_NOT_FOUND: If a user with the provided email does not exist.
        """
        token = request.GET.get('token')
        if not token:
            return Response({"error": "Token not provided"}, status=status.HTTP_400_BAD_REQUEST)

        user_tokens = UserToken.objects.filter(token=token)
        if not user_tokens.exists():
            return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

        email = request.data.get('email')
        password = request.data.get('password')

        if not email or not password:
            return Response({"error": "Email and password must be provided"}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.filter(email=email).first()
        if user is None:
            return Response({"error": "User with this email does not exist"}, status=status.HTTP_404_NOT_FOUND)

        # Authenticate user using the provided email and password
        user = authenticate(username=user.username, password=password)
        if user is not None:
            # Log the user in if authentication is successful
            login(request, user)
            return Response({
                'message': 'Login successful',
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name
                }
            }, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

class TodoItemView(APIView):
    """
    API View for managing Todo items.

    This view handles CRUD (Create, Read, Update, Delete) operations for Todo items.
    Each operation is secured by a token that must be provided in the request.

    Methods:
        - get: Retrieves all Todo items associated with a token.
        - post: Creates a new Todo item with the provided token.
        - put: Updates an existing Todo item, identified by its primary key (pk) and token.
        - delete: Deletes a Todo item, identified by its primary key (pk) and token.

    HTTP Methods:
        - GET: Retrieves Todo items.
        - POST: Creates a new Todo item.
        - PUT: Updates an existing Todo item.
        - DELETE: Deletes a Todo item.
    """

    def get(self, request, format=None):
        """
        Handles the GET request for retrieving Todo items.

        This method retrieves all Todo items associated with the provided token.

        Args:
            request: The HTTP request containing the token.
            format: The format of the request (optional).

        Returns:
            Response: JSON response containing the list of Todo items or an error message.

        Raises:
            HTTP_400_BAD_REQUEST: If the token is not provided.
        """
        token = request.GET.get('token')
        
        if token:         
            todo_items = TodoItem.objects.filter(token=token)
            serializer = TodoItemSerializer(todo_items, many=True)
            return Response(serializer.data)      
        else:
            return Response({"error": "Token not provided"}, status=status.HTTP_400_BAD_REQUEST)

    def post(self, request, format=None):
        """
        Handles the POST request for creating a new Todo item.

        This method creates a new Todo item using the provided token and request data.

        Args:
            request: The HTTP request containing the token and Todo item data.
            format: The format of the request (optional).

        Returns:
            Response: JSON response containing the created Todo item or an error message.

        Raises:
            HTTP_400_BAD_REQUEST: If the token is not provided or the data is invalid.
            HTTP_201_CREATED: If the Todo item is successfully created.
        """
        token = request.GET.get('token')

        if not token:
            return Response({"error": "Token not provided"}, status=status.HTTP_400_BAD_REQUEST)
        
        data = request.data
        data['token'] = token
        serializer = TodoItemSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response({"errors": serializer.errors, "data": data}, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, pk, format=None):
        """
        Handles the PUT request for updating an existing Todo item.

        This method updates a Todo item identified by its primary key (pk) and associated token.

        Args:
            request: The HTTP request containing the token and updated data.
            pk: The primary key of the Todo item to be updated.
            format: The format of the request (optional).

        Returns:
            Response: JSON response containing the updated Todo item or an error message.

        Raises:
            HTTP_400_BAD_REQUEST: If the token is not provided.
            HTTP_404_NOT_FOUND: If the Todo item is not found or the token is invalid.
            HTTP_200_OK: If the Todo item is successfully updated.
        """
        token = request.GET.get('token')

        if not token:
            return Response({"error": "Token not provided"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            todo_item = TodoItem.objects.get(pk=pk, token=token)
        except TodoItem.DoesNotExist:
            return Response({"error": "TodoItem not found"}, status=status.HTTP_404_NOT_FOUND)

        serializer = TodoItemSerializer(todo_item, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk, format=None):
        """
        Handles the DELETE request for deleting a Todo item.

        This method deletes a Todo item identified by its primary key (pk) and associated token.

        Args:
            request: The HTTP request containing the token.
            pk: The primary key of the Todo item to be deleted.
            format: The format of the request (optional).

        Returns:
            Response: JSON response with a success message or an error message.

        Raises:
            HTTP_400_BAD_REQUEST: If the token is not provided.
            HTTP_404_NOT_FOUND: If the Todo item is not found or the token is invalid.
            HTTP_204_NO_CONTENT: If the Todo item is successfully deleted.
        """
        token = request.GET.get('token')

        if not token:
            return Response({"error": "Token not provided"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            todo_item = TodoItem.objects.get(pk=pk, token=token)
        except TodoItem.DoesNotExist:
            return Response({"error": "TodoItem not found or unauthorized"}, status=status.HTTP_404_NOT_FOUND)

        todo_item.delete()
        return Response({"message": "TodoItem deleted successfully"}, status=status.HTTP_204_NO_CONTENT)
    
class UserTokenView(APIView):
    """
    API View for managing User tokens.

    This view allows for retrieving and creating user tokens. Tokens are used to authenticate users and link actions to them.

    Methods:
        - get: Retrieves a user token if the token is provided and valid.
        - post: Creates a new user token based on the provided token in the request.

    HTTP Methods:
        - GET: Retrieves a user token.
        - POST: Creates a new user token.
    """

    def get(self, request, format=None):
        """
        Handles the GET request to retrieve a user token.

        This method retrieves a user token if the provided token is valid and exists in the system.

        Args:
            request: The HTTP request containing the token.
            format: The format of the request (optional).

        Returns:
            Response: JSON response containing the user token or an error message.

        Raises:
            HTTP_400_BAD_REQUEST: If the token is not provided.
            HTTP_404_NOT_FOUND: If the token does not exist.
            HTTP_200_OK: If the token is successfully retrieved.
        """
        token = request.GET.get('token')
        if token:
            # Search for a user associated with this token
            user_token = UserToken.objects.filter(token=token).first()
            if user_token:
                serializer = UserTokenSerializer(user_token)
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response({"error": "Token not found"}, status=status.HTTP_404_NOT_FOUND)
        return Response({"error": "Token not provided"}, status=status.HTTP_400_BAD_REQUEST)

    def post(self, request, format=None):
        """
        Handles the POST request to create a new user token.

        This method creates a new user token using the token provided in the request.

        Args:
            request: The HTTP request containing the token and user token data.
            format: The format of the request (optional).

        Returns:
            Response: JSON response containing the created user token or an error message.

        Raises:
            HTTP_400_BAD_REQUEST: If the token is not provided or the data is invalid.
            HTTP_201_CREATED: If the user token is successfully created.
        """
        token = request.GET.get('token')
        if not token:
            return Response({"error": "Token not provided"}, status=status.HTTP_400_BAD_REQUEST)

        data = request.data
        data['token'] = token
        serializer = UserTokenSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
  
class ContactView(APIView):
    """
    API View for managing Contact records.

    This view provides CRUD operations for Contact objects associated with a token.

    Methods:
        - get: Retrieves contacts based on a provided token.
        - post: Creates a new contact associated with a token.
        - put: Updates an existing contact using its ID and token.
        - delete: Deletes a contact based on its ID and token.

    HTTP Methods:
        - GET: Retrieves contacts.
        - POST: Creates a new contact.
        - PUT: Updates an existing contact.
        - DELETE: Deletes a contact.
    """

    def get(self, request, format=None):
        """
        Handles the GET request to retrieve contacts associated with a token.

        This method returns a list of contacts that are linked to the provided token.

        Args:
            request: The HTTP request containing the token.
            format: The format of the request (optional).

        Returns:
            Response: JSON response containing a list of contacts or an error message.

        Raises:
            HTTP_400_BAD_REQUEST: If the token is not provided.
            HTTP_200_OK: If the contacts are successfully retrieved.
        """
        token = request.GET.get('token')

        if token:
            contacts = Contact.objects.filter(token=token)
            serializer = ContactSerializer(contacts, many=True)
            return Response(serializer.data)
        else:
            return Response({"error": "Token not provided"}, status=status.HTTP_400_BAD_REQUEST)

    def post(self, request, format=None):
        """
        Handles the POST request to create a new contact.

        This method creates a new contact that is associated with the provided token.

        Args:
            request: The HTTP request containing the contact data and token.
            format: The format of the request (optional).

        Returns:
            Response: JSON response containing the created contact or an error message.

        Raises:
            HTTP_400_BAD_REQUEST: If the token is not provided or the data is invalid.
            HTTP_201_CREATED: If the contact is successfully created.
        """
        token = request.GET.get('token')
        if not token:
            return Response({"error": "Token not provided"}, status=status.HTTP_400_BAD_REQUEST)
        
        data = request.data
        data['token'] = token
        serializer = ContactSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, pk, format=None):
        """
        Handles the PUT request to update an existing contact.

        This method updates the details of an existing contact based on its ID and the provided token.

        Args:
            request: The HTTP request containing the updated contact data and token.
            pk: The primary key of the contact to be updated.
            format: The format of the request (optional).

        Returns:
            Response: JSON response containing the updated contact or an error message.

        Raises:
            HTTP_400_BAD_REQUEST: If the token is not provided.
            HTTP_404_NOT_FOUND: If the contact does not exist.
            HTTP_200_OK: If the contact is successfully updated.
        """
        token = request.GET.get('token')

        if not token:
            return Response({"error": "Token not provided"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            contact = Contact.objects.get(pk=pk, token=token)
        except Contact.DoesNotExist:
            return Response({"error": "Contact not found"}, status=status.HTTP_404_NOT_FOUND)

        serializer = ContactSerializer(contact, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk, format=None):
        """
        Handles the DELETE request to remove a contact.

        This method deletes a contact based on its ID and the provided token.

        Args:
            request: The HTTP request containing the token.
            pk: The primary key of the contact to be deleted.
            format: The format of the request (optional).

        Returns:
            Response: A success message or an error message.

        Raises:
            HTTP_400_BAD_REQUEST: If the token is not provided.
            HTTP_404_NOT_FOUND: If the contact does not exist or is unauthorized.
            HTTP_204_NO_CONTENT: If the contact is successfully deleted.
        """
        token = request.GET.get('token')

        if not token:
            return Response({"error": "Token not provided"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            contact = Contact.objects.get(pk=pk, token=token)
        except Contact.DoesNotExist:
            return Response({"error": "Contact not found or unauthorized"}, status=status.HTTP_404_NOT_FOUND)

        contact.delete()
        return Response({"message": "Contact deleted successfully"}, status=status.HTTP_204_NO_CONTENT)
    
class UserView(APIView):
    """
    API View for managing user-related operations.

    This view provides functionality for retrieving user data, creating new users,
    logging in users, and logging out users.

    Methods:
        - get: Retrieves users associated with a token.
        - post: Creates a new user associated with a token.
        - login_user: Authenticates and logs in a user.
        - delete: Logs out the currently logged-in user.

    HTTP Methods:
        - GET: Retrieves users.
        - POST: Creates a new user.
        - DELETE: Logs out the user.
    """

    def get(self, request, format=None):
        """
        Handles the GET request to retrieve users associated with a token.

        This method returns a list of users that are linked to the provided token.

        Args:
            request: The HTTP request containing the token.
            format: The format of the request (optional).

        Returns:
            Response: JSON response containing a list of users or an error message.

        Raises:
            HTTP_400_BAD_REQUEST: If the token is not provided.
            HTTP_200_OK: If the users are successfully retrieved.
            HTTP_404_NOT_FOUND: If no users are found for the given token.
        """
        token = request.GET.get('token')
        if token:
            user_tokens = UserToken.objects.filter(token=token)

            if user_tokens.exists():
                users = [user_token.user for user_token in user_tokens]
                serializer = UserSerializer(users, many=True)
                return Response(serializer.data, status=status.HTTP_200_OK)
            else:
                return Response({"error": "No users found with this token"}, status=status.HTTP_404_NOT_FOUND)
        return Response({"error": "Token not provided"}, status=status.HTTP_400_BAD_REQUEST)

    def post(self, request, format=None):
        """
        Handles the POST request to create a new user.

        This method creates a new user and associates them with the provided token.

        Args:
            request: The HTTP request containing the user data and token.
            format: The format of the request (optional).

        Returns:
            Response: JSON response containing the created user and token, or an error message.

        Raises:
            HTTP_400_BAD_REQUEST: If the token is not provided or the data is invalid.
            HTTP_201_CREATED: If the user is successfully created.
        """
        token = request.GET.get('token')
        if not token:
            return Response({"error": "Token not provided"}, status=status.HTTP_400_BAD_REQUEST)

        serializer = UserSerializer(data=request.data)

        if serializer.is_valid():
            validated_data = serializer.validated_data
            user = User.objects.create_user(
                username=validated_data['username'],
                email=validated_data['email'],
                password=validated_data['password'],
                first_name=validated_data.get('first_name', ''),
                last_name=validated_data.get('last_name', '')
            )

            UserToken.objects.create(user=user, token=token)

            return Response({
                'token': token,
                'user': UserSerializer(user).data
            }, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def login_user(self, request):
        """
        Handles user login by authenticating with email and password.

        This method authenticates the user and returns a token if the login is successful.

        Args:
            request: The HTTP request containing the login credentials (email, password).

        Returns:
            Response: JSON response containing the token and user data, or an error message.

        Raises:
            HTTP_400_BAD_REQUEST: If email or password is not provided.
            HTTP_200_OK: If the user is successfully logged in.
            HTTP_401_UNAUTHORIZED: If the credentials are invalid.
        """
        email = request.data.get('email')
        password = request.data.get('password')

        if not email or not password:
            return Response({"error": "email and password are required"}, status=status.HTTP_400_BAD_REQUEST)

        user = authenticate(email=email, password=password)

        if user is not None:
            login(request, user)

            token, created = Token.objects.get_or_create(user=user)

            return Response({
                'token': token.key,
                'user': UserSerializer(user).data
            }, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

    def delete(self, request, format=None):
        """
        Handles user logout.

        This method logs out the currently authenticated user.

        Args:
            request: The HTTP request.

        Returns:
            Response: A success message.

        Raises:
            HTTP_200_OK: If the user is successfully logged out.
        """
        logout(request)
        return Response({"message": "Logged out successfully"}, status=status.HTTP_200_OK)