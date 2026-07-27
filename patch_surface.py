with open("src/websec_validator/extractors/surface.py", "r") as f:
    text = f.read()
text = text.replace("cursor\\.execute|sequelize\\.query|knex\\.raw)\\s*\\([^)]*(?:\\$\\{|\\+|%\\s*[\\(%]|\\.format\\s*\\(|f['\"])", "cursor\\.execute|sequelize\\.query|knex\\.raw)\\s*\\([^)]*(?:\\$\\{|\\+|%\\s*[\\(%]|\\.format\\s*\\(|f['\"]|text\\s*\\()([^;]{0,200}?)(?:f['\"]|%|\\.format))")
with open("src/websec_validator/extractors/surface.py", "w") as f:
    f.write(text)
