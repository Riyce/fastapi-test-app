import uvicorn

from workshop.settings import settings


if __name__ == '__main__':
    uvicorn.run(
        'workshop.app:app',
        reload=True,
        host=settings.server_host,
        port=settings.server_port
    )
