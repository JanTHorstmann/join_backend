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
    def post(self, request, format=None):
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

        user = authenticate(username=user.username, password=password)
        if user is not None:
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
    
    def get(self, request, format=None):
        token = request.GET.get('token')
        
        if token:         
                todo_items = TodoItem.objects.filter(token=token)
                serializer = TodoItemSerializer(todo_items, many=True)
                return Response(serializer.data)      
        else:
            return Response({"error": "Token not provided"}, status=status.HTTP_400_BAD_REQUEST)

    def post(self, request, format=None):
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

    def get(self, request, format=None):
        token = request.GET.get('token')
        if token:
            # Suche nach einem Benutzer mit diesem Token
            user_token = UserToken.objects.filter(token=token).first()
            if user_token:
                serializer = UserTokenSerializer(user_token)
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response({"error": "Token not found"}, status=status.HTTP_404_NOT_FOUND)
        return Response({"error": "Token not provided"}, status=status.HTTP_400_BAD_REQUEST)

    def post(self, request, format=None):
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

    def get(self, request, format=None):
        token = request.GET.get('token')

        if token:
            contacts = Contact.objects.filter(token=token)
            serializer = ContactSerializer(contacts, many=True)
            return Response(serializer.data)
        else:
            return Response({"error": "Token not provided"}, status=status.HTTP_400_BAD_REQUEST)

    def post(self, request, format=None):
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

    def get(self, request, format=None):
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
        email = request.data.get('email')
        password = request.data.get('password')

        if not email or not password:
            return Response({"error": "email and password are required"}, status=status.HTTP_400_BAD_REQUEST)

        user = authenticate(email=email, password=password)

        if user is not None:
            login(request, user)

            token = Token.objects.get_or_create(user=user)

            return Response({
                'token': token.key,
                'user': UserSerializer(user).data
            }, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)


    def delete(self, request, format=None):
        logout(request)
        return Response({"message": "Logged out successfully"}, status=status.HTTP_200_OK)

