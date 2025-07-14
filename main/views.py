from django.shortcuts import render, redirect
from django.views.decorators.http import require_http_methods

def home(request):
    return render(request, 'main/home.html')

