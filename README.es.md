# cortex9-mlflow-webhook-dns-rebinding-toctou-model

Modelo de comprobación y uso de **CVE-2026-64849** (GHSA-7gwp-5pfp-969j),
el SSRF en el envío de webhooks de MLflow: `_validate_webhook_url` resolvía
el host y exigía direcciones públicas, pero la petición lo resolvía **otra
vez** y conectaba sin volver a comprobar, así que una respuesta DNS de
rebinding (o una redirección) podía llegar a `169.254.169.254`,
`127.0.0.1` o a redes RFC 1918. Corregido en MLflow 3.15.0 con el commit
ba949522477c (PR #24258): `pre` = antes, `post` = después.

Educativo, offline, determinista y solo con la biblioteca estándar. No se
instala MLflow, requests ni urllib3. La resolución de nombres es un
**resolver falso determinista** (una tabla de respuestas por host,
consumida en orden); nunca se abre un socket y un test parchea `socket` para
que falle ante cualquier llamada. `11.0.0.1`/`11.0.0.2` son direcciones
públicas de relleno que nunca se contactan.

## Qué cambia el fix (líneas del diff guardado)

| Líneas | Cambio |
|---|---|
| 25 / 29 | `HTTPAdapter` → `SSRFProtectedHTTPAdapter` |
| 31-33 | `session.trust_env = False`: se ignoran los proxies del entorno |
| 45-50 | el docstring describe el TOCTOU: validar resuelve, `requests.post` vuelve a resolver |
| 82-108 | `_assert_public_peer`: opt-out (83-84), fallo de `getpeername` (88-94), IP inválida (95-101), `not ip.is_global` (103-108) |
| 111-131, 137-152, 162-186 | conexiones, pools y gestor de proxies protegidos |

`_validate_webhook_url` no está en el diff; su comportamiento se toma del
texto del GHSA.

## Evidencia diferencial

Los 8 positivos llegan a un par no público en `pre` y fallan cerrados en
`post`; los 5 negativos no cambian. En una malla de 23 × 23 pares
`[validación, conexión]`, `post` nunca llega a un par no público.

**Más allá del diff:** `64:ff9b::a9fe:a9fe` (forma NAT64 de
169.254.169.254) es `is_global` para `ipaddress`, así que `post` tal como
está en este diff lo deja pasar (`a07`). El GHSA dice que esos bypasses
IPv6 se corrigieron después (PR 25568, MLflow 3.16.0); eso **no** se
modela. Lo que el GHSA dice de `::ffff:100.64.0.0/10` no se reproduce con
Python 3.10–3.13 (`a09`).

## Uso

```sh
python3 tests/run.py
python3 scripts/derive_expected.py | diff - fixtures/expected.tsv
PYTHONPATH=src python3 -m mlflow_ssrf_model results fixtures/scenarios.json /tmp/r && diff -r results /tmp/r
```

Ejercicios en [PRACTICE.md](PRACTICE.md); límites en
[LIMITATIONS.md](LIMITATIONS.md); fuentes en [SOURCES.md](SOURCES.md).
Licencia: Apache-2.0.
