from django.shortcuts import render


def index(request):
    return render(request, "whoami/index.html")


def labs(request):
    return render(request, "whoami/labs.html")


def guide(request):
    return render(request, "whoami/guide.html")
