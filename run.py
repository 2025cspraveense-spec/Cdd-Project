"""Entry point for Secret Leak Guard v2.0 application server."""

import os
from app import create_app

env_name = os.getenv("FLASK_ENV", "development")
app = create_app(config_name=env_name)

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=app.config.get("DEBUG", False))
