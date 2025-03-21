"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const passport_1 = __importDefault(require("passport"));
const passport_local_1 = require("passport-local");
const passport_jwt_1 = require("passport-jwt");
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const bcrypt_1 = __importDefault(require("bcrypt"));
const app = (0, express_1.default)();
const PORT = 5000;
const SECRET_KEY = 'your_secret_key';
app.use(express_1.default.json());
// Mock user (хранится в памяти)
const user = {
    id: 1,
    username: 'testuser',
    password: bcrypt_1.default.hashSync('password123', 10),
};
// Passport Local Strategy (аутентификация по логину/паролю)
passport_1.default.use(new passport_local_1.Strategy((username, password, done) => {
    if (username !== user.username) {
        return done(null, false, { message: 'Пользователь не найден' });
    }
    if (!bcrypt_1.default.compareSync(password, user.password)) {
        return done(null, false, { message: 'Неверный пароль' });
    }
    return done(null, user);
}));
// Passport JWT Strategy (проверка токена)
passport_1.default.use(new passport_jwt_1.Strategy({
    jwtFromRequest: passport_jwt_1.ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: SECRET_KEY,
}, (jwt_payload, done) => {
    if (jwt_payload.id !== user.id) {
        return done(null, false);
    }
    return done(null, user);
}));
// Логин и получение JWT
app.post('/login', (req, res, next) => {
    passport_1.default.authenticate('local', { session: false }, (err, user, info) => {
        if (err || !user) {
            return res.status(400).json({ message: info ? info.message : 'Ошибка входа' });
        }
        const token = jsonwebtoken_1.default.sign({ id: user.id }, SECRET_KEY, { expiresIn: '1h' });
        return res.json({ token });
    })(req, res, next);
});
// Защищённый маршрут
app.get('/profile', passport_1.default.authenticate('jwt', { session: false }), (req, res) => {
    res.json({ message: 'Добро пожаловать в профиль!', user: req.user });
});
app.listen(PORT, () => console.log(`Сервер запущен на http://localhost:${PORT}`));
