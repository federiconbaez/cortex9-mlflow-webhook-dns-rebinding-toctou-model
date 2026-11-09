# Guía práctica (7 niveles)

Ejercicios **offline y locales** sobre un resolver falso. No hace falta
MLflow, DNS ni red. Cada respuesta está comprobada en
`tests/test_model.py` (`test_practice_level_N`).

**Alcance:** practica solo en tu propia máquina, en un laboratorio propio
(VM o contenedor local con tu propio MLflow) o en máquinas de
HTB/plataformas de práctica donde tengas autorización expresa. Nunca
contra servidores, DNS ni metadatos de nube de terceros.

Comando: `PYTHONPATH=src python3 -m mlflow_ssrf_model case pre|post <ip-validación> <ip-conexión>`.

**Básico**

1. **Todo público.** `11.0.0.1` y `11.0.0.1` en `pre`. (`DELIVERED`)
2. **El guardia funciona.** `127.0.0.1` desde el principio. ¿Qué
   resolución la detiene? (`REJECT_VALIDATION`, la primera)

**Intermedio**

3. **El TOCTOU.** `11.0.0.1` y luego `169.254.169.254` en `pre`. ¿Cuántas
   resoluciones hay y cuál se comprueba? (`REACHED_PRIVATE`; 2, solo la
   primera; docstring en líneas 45-50 del diff)
4. **El fix.** Lo mismo en `post`. ¿Qué línea decide?
   (`SSRF_ERROR`, líneas 29 y 103-108)
5. **IPv4 mapeada.** `::ffff:10.0.0.1` en `post`. (`SSRF_ERROR`)

**Avanzado**

6. **Proxy del entorno.** Escenario con `env_proxy=127.0.0.1` y destino
   público: compará `pre` y `post` y explicá la línea 33.
   (`REACHED_PRIVATE` → `DELIVERED`)
7. **Más allá del diff.** `64:ff9b::a9fe:a9fe` en `post`. ¿Por qué pasa y
   qué dice el GHSA del arreglo posterior? (`DELIVERED`; PR 25568, no
   modelado, no es un hallazgo)

**Defensa propia:** escribí, para un servicio propio de laboratorio, un
clasificador que normalice NAT64, 6to4 e IPv4 mapeadas antes de decidir, y
pasale la malla de `tests/test_model.py`. Agregá un escenario a
`fixtures/scenarios.json` con su etiqueta a mano, regenerá
`fixtures/expected.tsv` y comprobá que todo coincide.
