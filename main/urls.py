from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('evaluation/mid/', views.mid_evaluation, name='mid_evaluation'),
    path('evaluation/mid/form/<int:lecture_id>/', views.mid_eval_form, name='mid_eval_form'),
]