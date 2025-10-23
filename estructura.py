import os
import argparse

def _recorrer_directorio(directorio, prefijo="", ignorar_dirs=None, ignorar_archivos=None):
    """Función auxiliar recursiva que genera las líneas del árbol."""
    if ignorar_dirs is None: ignorar_dirs = set()
    if ignorar_archivos is None: ignorar_archivos = set()

    # Obtener y filtrar contenidos
    try:
        contenidos = [item for item in os.listdir(directorio) if item not in ignorar_dirs and not any(item.endswith(ext) for ext in ignorar_archivos)]
    except FileNotFoundError:
        return
    except PermissionError:
        yield f"{prefijo}└── [Error: Permiso denegado]"
        return

    directorios = sorted([d for d in contenidos if os.path.isdir(os.path.join(directorio, d))])
    archivos = sorted([a for a in contenidos if os.path.isfile(os.path.join(directorio, a))])
    
    elementos = directorios + archivos
    punteros = ['├── '] * (len(elementos) - 1) + ['└── ']

    for puntero, elemento in zip(punteros, elementos):
        yield f"{prefijo}{puntero}{elemento}"
        ruta_completa = os.path.join(directorio, elemento)
        
        if os.path.isdir(ruta_completa):
            extension = '│   ' if puntero == '├── ' else '    '
            yield from _recorrer_directorio(ruta_completa, prefijo + extension, ignorar_dirs, ignorar_archivos)

def generar_arbol_texto(directorio_raiz, archivo_salida, ignorar_dirs, ignorar_archivos):
    """
    Genera una representación en árbol en un archivo de texto.
    """
    with open(archivo_salida, 'w', encoding='utf-8') as f:
        f.write(f"🌳 Estructura del proyecto: {os.path.basename(directorio_raiz)}\n")
        for linea in _recorrer_directorio(directorio_raiz, "", ignorar_dirs, ignorar_archivos):
            f.write(linea + '\n')

def generar_arbol_imagen(directorio_raiz, archivo_salida, ignorar_dirs, ignorar_archivos):
    """
    Genera una representación en árbol en un archivo de imagen.
    """
    try:
        from PIL import Image, ImageDraw, ImageFont
    except ImportError:
        print("❌ Error: La librería 'Pillow' es necesaria para crear imágenes.")
        print("   Por favor, instálala con: pip install Pillow")
        return

    # Generar las líneas de texto primero
    titulo = f"🌳 Estructura del proyecto: {os.path.basename(directorio_raiz)}"
    lineas = [titulo] + list(_recorrer_directorio(directorio_raiz, "", ignorar_dirs, ignorar_archivos))

    # Configuración de la imagen y fuente
    padding = 20
    line_spacing = 5
    font_size = 15
    font_color = (0, 0, 0)
    bg_color = (255, 255, 255)

    try:
        # Intenta cargar una fuente monoespaciada común
        font = ImageFont.truetype("consola.ttf", font_size)
    except IOError:
        print("⚠️ Advertencia: Fuente 'consola.ttf' no encontrada. Usando fuente por defecto.")
        font = ImageFont.load_default()

    # Calcular dimensiones de la imagen
    max_width = 0
    total_height = 0
    line_height = 0

    for linea in lineas:
        bbox = font.getbbox(linea)
        line_width = bbox[2] - bbox[0]
        line_height = bbox[3] - bbox[1]
        if line_width > max_width:
            max_width = line_width
        total_height += line_height + line_spacing

    img_width = max_width + 2 * padding
    img_height = total_height + 2 * padding - line_spacing

    # Crear la imagen y dibujar el texto
    img = Image.new('RGB', (int(img_width), int(img_height)), bg_color)
    draw = ImageDraw.Draw(img)

    y = padding
    for linea in lineas:
        draw.text((padding, y), linea, font=font, fill=font_color)
        y += line_height + line_spacing

    img.save(archivo_salida)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Genera un árbol de directorios en formato texto o imagen.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        '-p', '--path',
        default='.',
        help="Ruta del directorio a analizar.\n(default: directorio actual)"
    )
    parser.add_argument(
        '-o', '--output',
        default='estructura',
        help="Nombre del archivo de salida (sin extensión).\n(default: 'estructura')"
    )
    parser.add-argument(
        '-f', '--format',
        choices=['txt', 'png'],
        default='txt',
        help="Formato del archivo de salida.\n(default: 'txt')"
    )
    parser.add_argument(
        '--ignore-dirs',
        nargs='*',
        default=['__pycache__', '.git', '.vscode', 'venv', 'node_modules'],
        help="Lista de directorios a ignorar.\n(default: __pycache__, .git, .vscode, venv, node_modules)"
    )
    parser.add_argument(
        '--ignore-files',
        nargs='*',
        default=['.gitignore', '.env', '.DS_Store'],
        help="Lista de archivos o extensiones a ignorar.\n(default: .gitignore, .env, .DS_Store)"
    )
    args = parser.parse_args()
    
    directorio_raiz = args.path
    archivo_salida = f"{args.output}.{args.format}"
    ignorar_dirs = set(args.ignore_dirs)
    ignorar_archivos = set(args.ignore_files)

    if not os.path.isdir(directorio_raiz):
        print(f"❌ Error: La ruta '{directorio_raiz}' no es un directorio válido.")
    else:
        if args.format == 'txt':
            generar_arbol_texto(directorio_raiz, archivo_salida, ignorar_dirs, ignorar_archivos)
        elif args.format == 'png':
            generar_arbol_imagen(directorio_raiz, archivo_salida, ignorar_dirs, ignorar_archivos)
        
        print(f"✅ ¡Árbol de directorios guardado en '{archivo_salida}'!")
