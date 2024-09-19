from django.contrib import admin
from django.urls import path
from todos.views import TodoItemView, ContactView, UserView, UserTokenView, LoginView

urlpatterns = [
    path('admin/', admin.site.urls),

    path('todos/', TodoItemView.as_view()),
    path('todos/<int:pk>/', TodoItemView.as_view()),

    path('contact/', ContactView.as_view()),
    path('contact/<int:pk>/', ContactView.as_view()),

    path('users/', UserView.as_view()),
    path('usertoken/', UserTokenView.as_view()),

    path('login/', LoginView.as_view()),
]
