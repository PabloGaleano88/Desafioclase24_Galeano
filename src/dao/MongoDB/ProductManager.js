import { productsModel } from '../models/productsModel.js'

class ProductManager {

    async create(title, description, price, code, category, stock, thumbnail) {
        const producto = await productsModel.create({
            title,
            description,
            price,
            code,
            status: true,
            category,
            stock,
            thumbnail: [thumbnail],
        })
        return producto
    }


    async getAll(urlQuery, urlLimit, urlPage, urlSort) {
        let response = {}

        try {

            const filter = urlQuery ? { [urlQuery.split(':')[0]]: urlQuery.split(':')[1] } : {}
                const sortMapper = {
                asc: { price: 1 },
                desc: { price: -1 }
            }

            const limitQuery = urlLimit ? parseInt(urlLimit, 10) : 10
            const pageQuery = urlPage ? parseInt(urlPage, 10) : 1
            const sortQuery = sortMapper[urlSort] ?? undefined

            const products = await productsModel.paginate(filter, {
                limit: limitQuery,
                page: pageQuery,
                sort: sortQuery,
                lean: true,
            })

            response = {
                status: 'success',
                payload: products.docs,
                totalDocs: products.totalDocs,
                limit: products.limit,
                totalPages: products.totalPages,
                page: products.page,
                pagingCounter: products.pagingCounter,
                hasPrevPage: products.hasPrevPage,
                hasNextPage: products.hasNextPage,
                prevPage: products.prevPage,
                nextPage: products.nextPage,
            };
        }
        catch (e) {
            response = {
                status: 'error',
                payload: null,
                totalDocs: null,
                limit: null,
                totalPages: null,
                page: null,
                pagingCounter: null,
                hasPrevPage: null,
                hasNextPage: null,
                prevPage: null,
                nextPage: null,
            }
        }

        return (response)
    }

    async delete(id) {
        await productsModel.findByIdAndDelete(id)
        return this.getAll()
    }

    async findById(id) {
        try {
            const product = await productsModel.findById(id)
            return product
        }
        catch (error) {
            return (`Producto con ID:${id} no encontrado`)
        }
    }

    async updateProduct(id, updateFields) {
        const fields = Object.keys(updateFields)
        fields.forEach(element => {
            if (element !== "title" && element !== "description" && element !== "price" && element !== "code" && element !== "category" && element !== "stock") {
                console.log(`${element} no es un campo valido por lo tanto no se actualizará`)
            }
        });
        try {
            await productsModel.findOneAndUpdate({ _id: id }, updateFields)

        }
        catch (error) {
            console.log(`se ha producido el siguiente error al intentar modificar el campo: ${error}`)
        }
        return this.findById(id)
    }
}
export default ProductManager
