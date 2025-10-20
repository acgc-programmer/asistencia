
-- Añadir ON DELETE CASCADE a la tabla 'asistencias'
-- Asume que ya existe una foreign key a 'cursos'. Si no, créala.
ALTER TABLE asistencias DROP CONSTRAINT asistencias_id_curso_fkey; -- Reemplaza 'asistencias_id_curso_fkey' con el nombre real de tu constraint
ALTER TABLE asistencias ADD CONSTRAINT asistencias_id_curso_fkey
    FOREIGN KEY (id_curso) REFERENCES cursos(id_curso) ON DELETE CASCADE;

-- Añadir ON DELETE CASCADE a la tabla 'horarios'
ALTER TABLE horarios DROP CONSTRAINT horarios_id_curso_fkey; -- Reemplaza con el nombre real
ALTER TABLE horarios ADD CONSTRAINT horarios_id_curso_fkey
    FOREIGN KEY (id_curso) REFERENCES cursos(id_curso) ON DELETE CASCADE;

-- Añadir ON DELETE CASCADE a la tabla 'asignatura'
ALTER TABLE asignatura DROP CONSTRAINT asignatura_id_curso_fkey; -- Reemplaza con el nombre real
ALTER TABLE asignatura ADD CONSTRAINT asignatura_id_curso_fkey
    FOREIGN KEY (id_curso) REFERENCES cursos(id_curso) ON DELETE CASCADE;

-- Añadir ON DELETE CASCADE a la tabla 'estudiantes_cursos'
ALTER TABLE estudiantes_cursos DROP CONSTRAINT estudiantes_cursos_id_curso_fkey; -- Reemplaza con el nombre real
ALTER TABLE estudiantes_cursos ADD CONSTRAINT estudiantes_cursos_id_curso_fkey
    FOREIGN KEY (id_curso) REFERENCES cursos(id_curso) ON DELETE CASCADE;

-- Finalmente, para que al eliminar un profesor se eliminen sus cursos (y todo lo demás en cascada)
ALTER TABLE cursos DROP CONSTRAINT cursos_id_profesor_fkey; -- Reemplaza con el nombre real
ALTER TABLE cursos ADD CONSTRAINT cursos_id_profesor_fkey
    FOREIGN KEY (id_profesor) REFERENCES profesores(id_profesor) ON DELETE CASCADE;
