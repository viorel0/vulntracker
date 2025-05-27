from django.shortcuts import render
from .forms import RegisterForm

def register(request):
    error = None
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.set_password(form.cleaned_data['password'])
            user.save()
            return render(request, 'registration_success.html')
        else:
            error="Invalid username or password"
    else:
        form = RegisterForm()
    return render(request, 'register.html', {'form': form, 'error': error})
