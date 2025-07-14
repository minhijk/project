from django.urls import path
from . import views

urlpatterns = [
    path('mid/', views.mid_evaluation, name='mid_evaluation'),
    path('final/', views.final_evaluation, name='final_evaluation'),
    path('mid/<int:lecture_id>/', views.mid_eval_form, name='mid_eval_form'),
    path('final/<int:lecture_id>/', views.final_eval_form, name='final_eval_form'),
]
