import express from 'express';
import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import { Strategy as JwtStrategy, ExtractJwt } from 'passport-jwt';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

const app = express();
const PORT = 5000;
const SECRET_KEY = 'your_secret_key';

app.use(express.json());

interface User {
    id: number;
    username: string;
    password: string;
}

const user: User = {
    id: 1,
    username: 'testuser',
    password: bcrypt.hashSync('password123', 10),
};

passport.use(
    new LocalStrategy((username: string, password: string, done) => {
        if (username !== user.username) {
            return done(null, false, { message: 'Пользователь не найден' });
        }
        if (!bcrypt.compareSync(password, user.password)) {
            return done(null, false, { message: 'Неверный пароль' });
        }
        return done(null, user);
    })
);

passport.use(
    new JwtStrategy(
        {
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            secretOrKey: SECRET_KEY,
        },
        (jwt_payload: any, done) => {
            if (jwt_payload.id !== user.id) {
                return done(null, false);
            }
            return done(null, user);
        }
    )
);

app.post('/login', (req, res, next) => {
    passport.authenticate('local', { session: false },  (err: Error | null, user: User | false, info: any) => {
        if (err || !user) {
            return res.status(400).json({ message: info ? info.message : 'Ошибка входа' });
        }
        const token = jwt.sign({ id: user.id }, SECRET_KEY, { expiresIn: '1h' });
        return res.json({ token });
    })(req, res, next);
});

app.get('/profile', passport.authenticate('jwt', { session: false }), (req, res) => {
    res.json({ message: 'Добро пожаловать в профиль!', user: req.user });
});

app.listen(PORT, () => console.log(`Сервер запущен на http://localhost:${PORT}`));
