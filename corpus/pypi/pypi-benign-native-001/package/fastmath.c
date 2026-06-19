/* Benign decoy fixture. A minimal, harmless C extension: one pure function. */
#include <Python.h>

static PyObject *fm_square(PyObject *self, PyObject *args) {
    double x;
    if (!PyArg_ParseTuple(args, "d", &x)) {
        return NULL;
    }
    return PyFloat_FromDouble(x * x);
}

static PyMethodDef Methods[] = {
    {"square", fm_square, METH_VARARGS, "Return x*x."},
    {NULL, NULL, 0, NULL},
};

static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT, "fastmath_ext", NULL, -1, Methods,
};

PyMODINIT_FUNC PyInit_fastmath_ext(void) {
    return PyModule_Create(&moduledef);
}
