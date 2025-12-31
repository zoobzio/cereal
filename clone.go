package codec

// Cloner allows types to provide deep copy logic.
// Implementing this interface is required for use with Serializer.
//
// The Clone method must return a deep copy where modifications to the clone
// do not affect the original value. For types containing pointers, slices, or maps,
// ensure these are also copied to achieve true isolation.
//
// For simple value types with no pointers, slices, or maps, Clone can simply return
// the receiver value:
//
//	func (u User) Clone() User { return u }
//
// For types with reference fields, ensure deep copying:
//
//	func (o Order) Clone() Order {
//	    items := make([]Item, len(o.Items))
//	    copy(items, o.Items)
//	    return Order{ID: o.ID, Items: items}
//	}
type Cloner[T any] interface {
	Clone() T
}
