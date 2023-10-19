import { Router } from "express";

import CartManager from '../dao/MongoDB/CartManager.js'
const cartManager = new CartManager('./src/carts.json')

const cartRouter = Router()

cartRouter.post('/',async (req,res) => {
    const {products} = req.body
    const result = await cartManager.addCart(products)
    res.status(200).send(result)
})

cartRouter.get('/:cid', async (req, res) => {
    const cid = req.params.cid
    const cartById = await cartManager.findCartById(cid)
    res.status(200).send(cartById)
})

cartRouter.post('/:cid/products/:pid',async (req,res) => {
    const cid = req.params.cid
    const pid = req.params.pid
    const result = await cartManager.addProductsToCart(cid,pid,1)
    res.status(200).send(result)
})

cartRouter.delete('/:cid/products/:pid', async (req, res) => {
    const cid = req.params.cid
    const pid = req.params.pid
    const result = await cartManager.removeProductFromCart(cid,pid)
    res.status(200).send(result)
})

cartRouter.put('/:cid',async (req,res)=>{
    const cid = req.params.cid
    const productUpdate = req.body
    const result = await cartManager.updateProducts(cid,productUpdate)
    res.status(200).send(result)
})

cartRouter.put('/:cid/products/:pid',async (req,res)=>{
    const cid = req.params.cid
    const pid = req.params.pid
    const {quantity}= req.body
    const result = await cartManager.updateProductQuantity(cid,pid,quantity)
    res.status(200).send(result)
})

cartRouter.delete('/:cid', async (req,res)=>{
    const cid = req.params.cid
    const result = await cartManager.removeAllProductsFromCart(cid)
    res.status(200).send(result)
})


export default cartRouter