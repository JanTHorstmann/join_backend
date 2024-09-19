from .models import TodoItem, Contact, UserToken
from rest_framework import serializers
from django.contrib.auth.models import User

class ContactSerializer(serializers.ModelSerializer):
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
    class Meta:
        model = UserToken
        fields = [
            'user',
            'token',
            ]

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    password_confirm = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'password', 'password_confirm', 'first_name', 'last_name']
    
    def validate(self, data):
        """
        Validiert, ob die beiden Passwörter übereinstimmen.
        """
        if data['password'] != data['password_confirm']:
            raise serializers.ValidationError("Die Passwörter stimmen nicht überein.")
        return data

    def create(self, validated_data):
        """
        Benutzer erstellen, nachdem die Passwörter übereinstimmen.
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
    email = serializers.CharField(required=True)
    password = serializers.CharField(required=True)

    def validate(self, data):
        return data

class TodoItemSerializer(serializers.ModelSerializer):
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
        assigned_to_data = validated_data.pop('assigned_to', [])

        request = self.context.get("request")
        author = request.user if request else None

        todo_item = TodoItem.objects.create(author=author, **validated_data)

        todo_item.assigned_to.set(assigned_to_data)

        return todo_item
        
