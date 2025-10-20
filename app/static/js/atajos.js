document.addEventListener('keydown', function(event) {
    // Verificar si el enfoque está en un campo de entrada (input, textarea)
    const isInputFieldFocused = document.activeElement.tagName === 'INPUT' || document.activeElement.tagName === 'TEXTAREA';

    // Solo ejecutar los atajos si no estamos escribiendo en un input o textarea
    if (isInputFieldFocused) {
        return;
    }

    // Comprobar si Shift + R fueron presionados
    if (event.shiftKey && event.key === 'R') {
        window.location.href = '/admin_registro';  // Redirige a la página de registro
    }
    
    // Comprobar si Ctrl + L fueron presionados
    if (event.shiftKey && event.key === 'L') {
        window.location.href = '/login';  // Redirigir al login
    }

    // Comprobar si Alt + S fueron presionados para enviar el formulario
    if (event.shiftKey && event.key === 'S') {
        document.querySelector('form').submit();  // Enviar el formulario
    }
});