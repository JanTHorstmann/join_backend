from .models import TodoItem, Contact, UserToken
from rest_framework import serializers
from django.contrib.auth.models import User

class ContactSerializer(serializers.ModelSerializer):
    """
    Serializer for the Contact model. This serializer is used to convert 
    the Contact model data into JSON format and vice versa.

    Fields:
        - id: The unique identifier for the contact.
        - name: The name of the contact.
        - email: The email address of the contact.
        - phone: The phone number of the contact.
        - inicials: The initials of the contact's name.
        - inicialcolor: The color associated with the contact's initials.
        - token: The token associated with the contact (for session filtering).
    """
    class Meta:
        model = Contact
        fields = [
            'id',
            'name', 
            'email', 
            'phone',
            'inicials',
            'inicialcolor',
            'token',
        ]

class UserTokenSerializer(serializers.ModelSerializer):
    """
    Serializer for the UserToken model. This serializer handles the relationship 
    between a user and their associated token.

    Fields:
        - user: The user associated with the token.
        - token: The unique token for the user (for session filtering).
    """
    class Meta:
        model = UserToken
        fields = [
            'user',
            'token',
        ]

class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for the User model, used for user registration and updates.
    Includes password validation for creating or updating a user.

    Fields:
        - id: The unique identifier for the user.
        - username: The username of the user.
        - email: The user's email address.
        - password: The user's password (write-only).
        - password_confirm: A confirmation for the password (write-only).
        - first_name: The user's first name.
        - last_name: The user's last name.
    """
    password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    password_confirm = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'password', 'password_confirm', 'first_name', 'last_name']
    
    def validate(self, data):
        """
        Validate that the provided passwords match.

        Raises:
            serializers.ValidationError: If the passwords do not match.
        """
        if data['password'] != data['password_confirm']:
            raise serializers.ValidationError("Passwords do not match.")
        return data

    def create(self, validated_data):
        """
        Create a new user instance after ensuring the passwords match.
        
        Args:
            validated_data (dict): Validated data from the request.

        Returns:
            user: A newly created user instance.
        """
        validated_data.pop('password_confirm')
        user = User(
            username=validated_data['username'],
            email=validated_data['email'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', ''),
        )

        user.set_password(validated_data['password'])
        user.save()
        return user

class LoginSerializer(serializers.Serializer):
    """
    Serializer for handling user login. This is used to validate login credentials.

    Fields:
        - email: The email of the user trying to log in.
        - password: The password of the user.
    """
    email = serializers.CharField(required=True)
    password = serializers.CharField(required=True)

    def validate(self, data):
        """
        Validate login data.
        
        Returns:
            dict: The validated data.
        """
        return data

class TodoItemSerializer(serializers.ModelSerializer):
    """
    Serializer for the TodoItem model. This serializer is responsible for 
    converting TodoItem data into JSON format and vice versa.

    Fields:
        - id: The unique identifier for the todo item.
        - title: The title of the todo item.
        - description: A brief description of the todo item.
        - due_date: The due date for the todo item.
        - priority: The priority level of the todo item.
        - category: The category this todo item belongs to.
        - subtasks: A list of subtasks associated with the todo item.
        - created_at: The date and time when the todo item was created.
        - assigned_to: A list of contacts the todo item is assigned to.
        - token: The token associated with this todo item (for session filtering).
        - inWichSection: Indicates which section the todo item belongs to.
    """
    assigned_to = serializers.PrimaryKeyRelatedField(many=True, queryset=Contact.objects.all())

    class Meta:
        model = TodoItem
        fields = [
            'id', 
            'title', 
            'description', 
            'due_date', 
            'priority', 
            'category', 
            'subtasks', 
            'created_at',
            'assigned_to',
            'token',
            'inWichSection',
        ]

    def create(self, validated_data):
        """
        Create a new TodoItem instance with the associated contacts.

        Args:
            validated_data (dict): Validated data from the request.

        Returns:
            todo_item: A newly created TodoItem instance.
        """
        assigned_to_data = validated_data.pop('assigned_to', [])

        request = self.context.get("request")
        author = request.user if request else None

        todo_item = TodoItem.objects.create(author=author, **validated_data)

        todo_item.assigned_to.set(assigned_to_data)

        return todo_item