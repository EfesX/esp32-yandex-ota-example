Тестовый проект для демонстрации беспроводного обновления прошивки (OTA) в микроконтроллере ESP32

Прошивка загружается из облачного сервиса [Yandex Object Storage](https://cloud.yandex.ru/docs/storage/)

Для доступа к бакету Yandex Object Storage, содержащему прошивку, настраивается мост в [Yandex API Gateway](https://cloud.yandex.ru/docs/api-gateway/)

Конфигурация WI-Fi точки доступа и адрес сервера API-Gateway настраивается при вызове idf.py menuconfig в меню "WIFI Setup" и "Yandex Setup"

