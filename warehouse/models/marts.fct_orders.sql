-- Fact table of orders with a flag for orders that do not count as revenue.
select
    order_id,
    customer_id,
    product_id,
    category,
    quantity,
    amount,
    status,
    status in ('cancelled', 'returned') as is_cancelled_or_returned,
    order_date
from staging.stg_orders
