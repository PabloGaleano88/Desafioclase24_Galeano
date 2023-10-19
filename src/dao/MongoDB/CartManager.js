import { cartsModel } from '../models/cartsModel.js'
import { productsModel } from '../models/productsModel.js'

class CartManager {
    async addCart() {
        try{
            const cart = await cartsModel.create({
            })
            return cart
        }
        catch(e){
            return (`error al agregar el carrito\n${e.name}\n${e.message}`)
        }
    }

    async findCartById(id) {
        try{
            const cart = await cartsModel.find({_id : id}).lean()
            return cart
        }
        catch(e){
            return("ID del carrito no encontrado")
        }
    }

    async addProductsToCart(cid, pid, quantity) {
        try {
            const cart = await cartsModel.findOne({_id: cid})
            await productsModel.findById(pid)
            const productInCart = cart.products.find(({productId}) =>productId.toString() === pid)
            if (productInCart) {
                productInCart.quantity += 1
            }
            
            else {
                cart.products.push({ productId: pid, "quantity": quantity })
            }
            
            await cart.save()
            const cartUpdated = await this.findCartById(cid)
            return cartUpdated
        }
        catch (error) {
                console.log("hola")
                return (`Revisa los datos ingresados.Ocurrió el siguiente error\n${e.name}\n${e.message}`)
            }
        }

    async removeProductFromCart(cartId, productId) {
        try{
            await productsModel.findById(productId)
            const cart = await cartsModel.findById(cartId)
            const products = cart.products.filter((p) => !p.productId.equals(productId))
            cart.products = products
            await cart.save()
            return cart
        }
        catch(e){
            return(`Ocurrió un error al intentar eliminar el carrito, revisa el ID del carrito y/o producto\n${e.name}\n${e.message}`)
        }
    }

    async removeAllProductsFromCart(cartId) {
        const cart = await cartsModel.findById(cartId)
        cart.products = []
        await cart.save()
        return cart
    }

    async updateProducts(cartId, productUpdate) {
        try{
            const cart = await cartsModel.findById(cartId)
            await this.removeAllProductsFromCart(cartId)
            cart.products.push(productUpdate)
            await cart.save()
            const cartUpdated = await cartsModel.findById(cartId)
            return cartUpdated
        }
        catch(e){
            return(`Ocurrió un error al intentar realizar la actualización, los datos ingresador \n${e.name}\n${e.message}`)
        }
    }

    async updateProductQuantity(cartId, productId, quantity) {
        try{
            const cart = await cartsModel.findById(cartId)
            await productsModel.findById(productId)
            const productIndex = cart.products.findIndex((p) => p.productId.equals(productId))
            if (productIndex !== -1) {
                cart.products[productIndex].quantity = quantity
                await cart.save()
            }
            return cart
        }
        catch(e){
            return(`Ocurrió un error al intentar actualizar la cantidad del producto\n Revisa el id del carrito o del producto\n${e.name}\n${e.message}`)
        }
    }
}

export default CartManager
