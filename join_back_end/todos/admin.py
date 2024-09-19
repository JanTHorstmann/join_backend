from django.contrib import admin
from .models import TodoItem, Contact, UserToken

class TodoItemAdmin(admin.ModelAdmin):
    list_display = ('title', 'id','due_date', 'priority', 'category', 'author', 'token')

    search_fields = ('title', 'id','description', 'author__username', 'token')

    list_filter = ('priority', 'id','category', 'due_date', 'author')

    fields = ('title', 'description', 'due_date', 'priority', 'category', 'subtasks', 'assigned_to', 'author', 'token', 'inWichSection')

    readonly_fields = ('created_at',)

admin.site.register(TodoItem, TodoItemAdmin)

class ContactAdmin(admin.ModelAdmin):
    list_display = ('name', 'id','email', 'phone', 'inicials', 'inicialcolor', 'token')

    search_fields = ('name', 'id','email', 'phone', 'inicials', 'inicialcolor')

    fields = ('name', 'email', 'phone', 'inicials', 'inicialcolor', 'token')

admin.site.register(Contact, ContactAdmin)

class UserTokenAdmin(admin.ModelAdmin):
    list_display = ('get_username', 'get_email', 'token')

    search_fields = ('user__username', 'user__email', 'token')

    def get_username(self, obj):
        return obj.user.username
    get_username.short_description = 'Username'

    def get_email(self, obj):
        return obj.user.email
    get_email.short_description = 'Email'

admin.site.register(UserToken, UserTokenAdmin)