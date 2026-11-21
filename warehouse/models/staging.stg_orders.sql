-- Orders joined to their product. One row per order.
select
    o.order_id,
    o.customer_id,
    o.product_id,
    p.category,
    o.quantity,
    o.amount,
    o.status,
    o.order_date
from raw.orders o
left join raw.products p using (product_id)
