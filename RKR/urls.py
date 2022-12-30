from django.urls import path
from RKR import views

urlpatterns = [

    path("", views.home, name='home'),
    path("purchase", views.purchase, name='purchase'),
    path("tracker", views.tracker, name='TrackingStatus'),
    path("checkout/", views.checkout, name='Checkout'),
    path("handlerequest/", views.handlerequest, name='HandleRequest'),
]