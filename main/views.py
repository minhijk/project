from django.shortcuts import render
from django.http import HttpResponse
# Create your views here.



def home(request):
    return render(request, 'main/home.html')

def mid_evaluation(request):
    dummy_range = range(1, 9)  # 1~8까지 반복용 더미
    return render(request, 'main/mid_evaluation.html', {'dummy_range': dummy_range})

