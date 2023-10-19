import { Router } from "express";
import ProductManager from '../dao/MongoDB/ProductManager.js'
import CartManager from "../dao/MongoDB/CartManager.js";
import publicRoutes from "../middlewares/publicRoutes.js";
import privateRoutes from "../middlewares/privateRoutes.js";
const productManager = new ProductManager()
const cartManager = new CartManager()

const rtRouter = Router()


rtRouter.get('/', async (req, res) => {
    const { limit, page, sort, query } = req.query
    const result = await productManager.getAll(query, limit, page, sort)
    res.send(result)
})

rtRouter.get('/realtimeproducts', async (req, res) => {
    res.render('realTimeProducts', { style: 'realTimeProducts.css' })
})

rtRouter.get('/chat', (req, res) => {
    res.render('chat', { style: 'chat.css' })
})

rtRouter.get('/products', privateRoutes, async (req, res) => {
    const { limit, page, sort, query } = req.query
    const { first_name, last_name, email, age, admin } = req.session
    const result = await productManager.getAll(query, limit, page, sort)
    if (!page) {
        const prevLink = result.hasPrevPage ? `http://localhost:8080/products?page=${result.prevPage}&limit=${result.limit}` : false
        const nextLink = result.hasNextPage ? `http://localhost:8080/products?page=${result.nextPage}&limit=${result.limit}` : false
        const products = result.payload
        res.render('products', { products, prevLink, nextLink, first_name, last_name, email, age, admin, style: 'products.css' })
    }
    else {
        const pageExists = parseInt(page)
        if (pageExists > result.totalPages || isNaN(pageExists) || pageExists < 1) {
            res.render('error')
        }
        else {
            const prevLink = result.hasPrevPage ? `http://localhost:8080/products?page=${result.prevPage}&limit=${result.limit}` : false
            const nextLink = result.hasNextPage ? `http://localhost:8080/products?page=${result.nextPage}&limit=${result.limit}` : false
            const products = result.payload
            res.render('products', { products, prevLink, nextLink, first_name, last_name, email, age, admin, style: 'products.css' })
        }
    }
})

rtRouter.get('/login', publicRoutes, (req, res) => {
    const login_fail = req.query.login_fail === 'true';
    res.render('login', { style: 'login.css', login_fail });
})

rtRouter.get('/signup', publicRoutes, (req, res) => {
    res.render('signup', { style: 'signup.css' })
})

rtRouter.get('/carts/:cid', async (req, res) => {
    const cid = req.params.cid
    const cartById = await cartManager.findCartById(cid)
    const productsOnCart = cartById[0].products
    res.render('carts', { productsOnCart, style: 'carts.css' })
})


export default rtRouter