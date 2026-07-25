# Font.h — восстановление

`include/ImGui/font/Font.h` весит 6.89 МБ (C-массив с TTF шрифта OPPOSans_H,
2.2 МБ). GitHub Contents API режет запросы больше 4 МБ, поэтому файл лежит
как gzip + base64, разбитый на две части.

Собрать обратно:

```bash
cd EclipsNormal/include/ImGui/font
cat Font.h.gz.b64.part00 Font.h.gz.b64.part01 | base64 -d | gunzip > Font.h
```

Проверка: `wc -c Font.h` должно дать ровно `6890661`.

Без этого файла сборка падает — `include/Android_draw/draw.h:27` его инклюдит.
